"""Validate that a packaged One Link artifact matches current source.

This is the release-side guard for the stale-tarball class of bug:
source may be green while the public binary is old or missing dynamic
imports/package data. The validator is intentionally split into cheap
static checks and optional live probes so CI can run the static gate on
every build, while a release operator can point it at a launched packaged
daemon for the network-facing checks.

Examples:

    python scripts/validate_packaged_artifact.py \
      --artifact dist/one-link/one-link.exe \
      --spec build/one-link.spec

    python scripts/validate_packaged_artifact.py \
      --artifact dist/one-link/one-link.exe \
      --spec build/one-link.spec \
      --base-url https://192.168.1.142:7118 \
      --cacert "%LOCALAPPDATA%/One_link/data/peer_https/root_ca.pem"
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


REQUIRED_HIDDEN_IMPORTS = (
    "one_link.sessions",
    "one_link.recovery_api",
)
REQUIRED_DATA_FRAGMENTS = (
    "one_link/web",
    "one_link/data",
)
REQUIRED_PEER_HEADERS = {
    "cache-control": ("no-cache", "must-revalidate"),
    "etag": ('"',),
}
DEFAULT_VERSION_TIMEOUT = 15.0


class GateFailure(RuntimeError):
    pass


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_source_version(repo: Path) -> str:
    ns: dict[str, Any] = {}
    init_py = repo / "src" / "one_link" / "__init__.py"
    exec(init_py.read_text(encoding="utf-8"), ns)
    version = str(ns.get("__version__") or "").strip()
    if not version:
        raise GateFailure(f"could not read __version__ from {init_py}")
    return version


def _normalize_text(text: str) -> str:
    return text.replace("\\", "/")


def validate_spec(spec_path: Path) -> list[str]:
    if not spec_path.is_file():
        raise GateFailure(f"spec file not found: {spec_path}")
    text = _normalize_text(spec_path.read_text(encoding="utf-8"))
    missing = [m for m in REQUIRED_HIDDEN_IMPORTS if m not in text]
    missing += [d for d in REQUIRED_DATA_FRAGMENTS if d not in text]
    if "collect_all('one_link_native')" not in text:
        missing.append("collect_all('one_link_native') or intentional native-less evidence")
    if missing:
        raise GateFailure(
            "generated PyInstaller spec is missing: " + ", ".join(missing)
        )
    return [
        "spec includes dynamic imports: " + ", ".join(REQUIRED_HIDDEN_IMPORTS),
        "spec includes package data: " + ", ".join(REQUIRED_DATA_FRAGMENTS),
    ]


def _find_artifact_executable(artifact: Path) -> Path:
    if artifact.is_file():
        return artifact
    if not artifact.is_dir():
        raise GateFailure(f"artifact path not found: {artifact}")
    candidates = [
        artifact / "one-link.exe",
        artifact / "one-link",
        artifact / "One Link.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c
    matches = [
        p for p in artifact.iterdir()
        if p.is_file() and p.name.lower().startswith("one-link")
    ]
    if matches:
        return matches[0]
    raise GateFailure(f"no one-link executable found under {artifact}")


def validate_version(artifact: Path, expected_version: str) -> str:
    exe = _find_artifact_executable(artifact)
    try:
        proc = subprocess.run(
            [str(exe), "--version"],
            capture_output=True,
            text=True,
            timeout=DEFAULT_VERSION_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GateFailure(f"could not run {exe} --version: {e}") from e
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        raise GateFailure(
            f"{exe} --version exited {proc.returncode}: {out.strip()}"
        )
    if expected_version not in out:
        raise GateFailure(
            f"packaged version mismatch: expected {expected_version!r}, "
            f"got {out.strip()!r}"
        )
    return f"artifact --version reports {expected_version}"


def _request(
    url: str,
    *,
    token: str | None = None,
    cacert: Path | None = None,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    data = None
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context(
            cafile=str(cacert) if cacert is not None else None
        )
        if cacert is None:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return (
                int(resp.status),
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read(),
            )
    except urllib.error.HTTPError as e:
        return (
            int(e.code),
            {k.lower(): v for k, v in e.headers.items()},
            e.read(),
        )


def validate_peer_headers(base_url: str, cacert: Path | None) -> str:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "peer")
    status, headers, body = _request(url, cacert=cacert)
    if status != 200:
        raise GateFailure(f"GET /peer returned HTTP {status}: {body[:120]!r}")
    for name, needles in REQUIRED_PEER_HEADERS.items():
        value = headers.get(name, "")
        if not all(n in value for n in needles):
            raise GateFailure(f"/peer header {name!r} invalid: {value!r}")
    peer_markers = (
        b"<title>One Link",
        b"daemon-global-search-input",
        b"setup_device_invite",
        b"cert-authed reconnect",
    )
    missing = [m.decode("ascii", "ignore") for m in peer_markers if m not in body]
    if missing:
        raise GateFailure(
            "/peer response does not look like current peer.html; "
            "missing markers: " + ", ".join(missing)
        )
    return "/peer has ETag and no-cache/must-revalidate headers"


def validate_recovery_routes(base_url: str, token: str | None, cacert: Path | None) -> str:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "api/v1/recovery/status")
    status, _headers, body = _request(url, token=token, cacert=cacert)
    if not token and status in (401, 403):
        return "recovery route exists and is auth-gated"
    if status != 200:
        raise GateFailure(f"recovery status returned HTTP {status}: {body[:160]!r}")
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as e:
        raise GateFailure(f"recovery status returned invalid JSON: {e}") from e
    for key in ("phrase", "social", "backup", "any_ready"):
        if key not in payload:
            raise GateFailure(f"recovery status missing key {key!r}")
    return "recovery status route returns all recovery tracks"


def validate_alpn(base_url: str, cacert: Path | None) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "https":
        return "ALPN probe skipped for non-HTTPS base URL"
    host = parsed.hostname
    if not host:
        raise GateFailure(f"invalid HTTPS base URL: {base_url!r}")
    port = parsed.port or 443
    ctx = ssl.create_default_context(
        cafile=str(cacert) if cacert is not None else None
    )
    if cacert is None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            selected = ssock.selected_alpn_protocol()
    if selected != "http/1.1":
        raise GateFailure(f"expected ALPN http/1.1, got {selected!r}")
    return "HTTPS ALPN selects http/1.1"


def validate_cert_chain_with_openssl(base_url: str, cacert: Path | None) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "https":
        return "cert-chain probe skipped for non-HTTPS base URL"
    host = parsed.hostname
    if not host:
        raise GateFailure(f"invalid HTTPS base URL: {base_url!r}")
    port = parsed.port or 443
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-showcerts",
        "-alpn",
        "h2,http/1.1",
    ]
    if cacert is not None:
        cmd.extend(["-CAfile", str(cacert)])
    try:
        proc = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=12,
        )
    except FileNotFoundError:
        return _validate_cert_chain_with_python_ssl(host, port, cacert)
    except subprocess.TimeoutExpired as e:
        raise GateFailure("openssl s_client timed out") from e
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    cert_count = out.count("-----BEGIN CERTIFICATE-----")
    if cert_count < 2:
        raise GateFailure(f"expected 2+ certs in TLS chain, got {cert_count}")
    if "ALPN protocol: http/1.1" not in out and "ALPN protocol: h2" in out:
        raise GateFailure("openssl negotiated h2; Safari will hang")
    return f"TLS serves a chain with {cert_count} certificates"


def _validate_cert_chain_with_python_ssl(
    host: str,
    port: int,
    cacert: Path | None,
) -> str:
    ctx = ssl.create_default_context(
        cafile=str(cacert) if cacert is not None else None
    )
    if cacert is None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            selected = ssock.selected_alpn_protocol()
            chain_fn = (
                getattr(ssock, "get_verified_chain", None)
                or getattr(ssock, "get_unverified_chain", None)
            )
            chain = chain_fn() if chain_fn is not None else []
    if selected == "h2":
        raise GateFailure("Python ssl negotiated h2; Safari will hang")
    if len(chain) < 2:
        raise GateFailure(
            f"expected 2+ certs in TLS chain, got {len(chain)}"
        )
    return f"TLS serves a chain with {len(chain)} certificates"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Validate a packaged One Link artifact against current source.",
    )
    p.add_argument("--artifact", type=Path, required=True,
                   help="packaged executable or onedir bundle")
    p.add_argument("--spec", type=Path, default=Path("build/one-link.spec"),
                   help="generated PyInstaller spec to inspect")
    p.add_argument("--repo", type=Path, default=_repo_root(),
                   help="repo root containing src/one_link")
    p.add_argument("--skip-version", action="store_true",
                   help="skip running artifact --version")
    p.add_argument("--allow-native-missing", action="store_true",
                   help="allow spec without collect_all('one_link_native')")
    p.add_argument("--base-url", default="",
                   help="optional live packaged daemon URL, e.g. https://LAN:7118")
    p.add_argument("--token", default=os.environ.get("ONE_LINK_UI_TOKEN", ""),
                   help="optional UI bearer token for guarded live routes")
    p.add_argument("--cacert", type=Path, default=None,
                   help="optional root CA for live HTTPS probes")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    checks: list[str] = []
    try:
        source_version = _load_source_version(args.repo)
        spec_text = args.spec.read_text(encoding="utf-8") if args.spec.exists() else ""
        if args.allow_native_missing and "collect_all('one_link_native')" not in spec_text:
            patched = args.spec
            checks.extend(validate_spec_allowing_native_missing(patched))
        else:
            checks.extend(validate_spec(args.spec))
        if not args.skip_version:
            checks.append(validate_version(args.artifact, source_version))
        if args.base_url:
            cacert = args.cacert if args.cacert and args.cacert.exists() else None
            checks.append(validate_peer_headers(args.base_url, cacert))
            checks.append(validate_recovery_routes(args.base_url, args.token or None, cacert))
            checks.append(validate_alpn(args.base_url, cacert))
            checks.append(validate_cert_chain_with_openssl(args.base_url, cacert))
    except GateFailure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print("PACKAGED ARTIFACT PARITY: PASS")
    for c in checks:
        print(f"  - {c}")
    return 0


def validate_spec_allowing_native_missing(spec_path: Path) -> list[str]:
    if not spec_path.is_file():
        raise GateFailure(f"spec file not found: {spec_path}")
    text = _normalize_text(spec_path.read_text(encoding="utf-8"))
    missing = [m for m in REQUIRED_HIDDEN_IMPORTS if m not in text]
    missing += [d for d in REQUIRED_DATA_FRAGMENTS if d not in text]
    if missing:
        raise GateFailure(
            "generated PyInstaller spec is missing: " + ", ".join(missing)
        )
    return [
        "spec includes dynamic imports: " + ", ".join(REQUIRED_HIDDEN_IMPORTS),
        "spec includes package data: " + ", ".join(REQUIRED_DATA_FRAGMENTS),
        "native extension intentionally allowed missing",
    ]


if __name__ == "__main__":
    raise SystemExit(main())

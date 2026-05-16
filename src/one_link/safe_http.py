"""Small HTTP guardrails for local-control and update fetches."""

from __future__ import annotations

import ipaddress
import urllib.parse
import urllib.request
from typing import Any


def _is_loopback_host(hostname: str | None) -> bool:
    host = (hostname or "").strip().lower()
    if host in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validated_urlopen(
    request: urllib.request.Request | str,
    *,
    timeout: float,
    allow_https: bool = True,
    allow_loopback_http: bool = False,
    **kwargs: Any,
):
    """Open only explicitly permitted URL shapes.

    Bandit's B310 warning is right in spirit: raw urlopen can touch file,
    ftp, custom, or accidental LAN URLs. One Link only needs two cases:
    public HTTPS release fetches, and loopback HTTP calls to our own daemon.
    """
    url = request.full_url if isinstance(request, urllib.request.Request) else str(request)
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme == "https" and allow_https:
        pass
    elif scheme == "http" and allow_loopback_http and _is_loopback_host(parsed.hostname):
        pass
    else:
        raise ValueError(f"refusing URL with unsupported scheme/host: {url!r}")
    return urllib.request.urlopen(request, timeout=timeout, **kwargs)  # nosec B310

"""Small HTTP guardrails for local-control and update fetches."""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


MAX_HTTP_REDIRECTS = 8


def _is_loopback_host(hostname: str | None) -> bool:
    host = (hostname or "").strip().lower().rstrip(".")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # OS resolvers accept abbreviated IPv4 spellings such as 127.1 that
        # ipaddress intentionally rejects. Recognize those without DNS.
        try:
            import socket

            return ipaddress.ip_address(
                socket.inet_ntoa(socket.inet_aton(host)),
            ).is_loopback
        except OSError:
            return False


def _is_forbidden_public_host(hostname: str | None) -> bool:
    """Reject explicit local/non-global destinations on public fetches.

    Hostname resolution remains the transport's responsibility, but literal
    IPs (including abbreviated IPv4 accepted by OS resolvers) and localhost
    aliases are rejected before any socket is opened.
    """

    host = (hostname or "").strip().lower().rstrip(".")
    if not host or host == "localhost" or host.endswith(".localhost"):
        return True
    if "%" in host:  # scoped IPv6 / ambiguous zone identifier
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        try:
            import socket

            return not ipaddress.ip_address(
                socket.inet_ntoa(socket.inet_aton(host)),
            ).is_global
        except OSError:
            return False


def _validate_url(
    url: str,
    *,
    allow_https: bool,
    allow_loopback_http: bool,
) -> None:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError(f"refusing URL with unsupported scheme/host: {url!r}")
    if (
        scheme == "https"
        and allow_https
        and not _is_forbidden_public_host(parsed.hostname)
    ):
        return
    if scheme == "http" and allow_loopback_http and _is_loopback_host(parsed.hostname):
        return
    raise ValueError(f"refusing URL with unsupported scheme/host: {url!r}")


class _ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Apply the same URL policy to every redirect hop.

    Validating only the caller-supplied URL is not sufficient because
    ``urllib`` follows redirects automatically.  Without this handler, an
    otherwise allowed HTTPS metadata endpoint can bounce a privileged local
    process to a LAN/loopback HTTP service.
    """

    def __init__(self, *, allow_https: bool, allow_loopback_http: bool) -> None:
        super().__init__()
        self._allow_https = bool(allow_https)
        self._allow_loopback_http = bool(allow_loopback_http)

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        count = int(getattr(req, "_one_link_redirect_count", 0) or 0)
        if count >= MAX_HTTP_REDIRECTS:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                f"redirect limit exceeded ({MAX_HTTP_REDIRECTS})",
                headers,
                fp,
            )
        resolved_url = urllib.parse.urljoin(req.full_url, str(newurl))
        _validate_url(
            resolved_url,
            allow_https=self._allow_https,
            allow_loopback_http=self._allow_loopback_http,
        )
        redirected = super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            resolved_url,
        )
        if redirected is not None:
            setattr(redirected, "_one_link_redirect_count", count + 1)
        return redirected


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
    _validate_url(
        url,
        allow_https=allow_https,
        allow_loopback_http=allow_loopback_http,
    )

    # ``urlopen`` only exposes ``context`` as a keyword-only transport
    # option.  Preserve that supported surface while installing our redirect
    # policy; reject unknown kwargs rather than silently dropping security or
    # TLS configuration supplied by a future caller.
    context = kwargs.pop("context", None)
    if kwargs:
        unexpected = ", ".join(sorted(str(key) for key in kwargs))
        raise TypeError(f"unsupported validated_urlopen arguments: {unexpected}")
    handlers: list[Any] = [
        _ValidatedRedirectHandler(
            allow_https=allow_https,
            allow_loopback_http=allow_loopback_http,
        ),
    ]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    return opener.open(request, timeout=timeout)  # nosec B310

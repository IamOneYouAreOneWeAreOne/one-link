"""Native URL protocol handoff helpers for One Link."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse


_INVITE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,8192}$")


def _validate_invite_token(token: str) -> str:
    token = str(token or "").strip()
    if not token:
        raise ValueError("self-mesh enroll link missing token")
    if not _INVITE_TOKEN_RE.fullmatch(token):
        raise ValueError("self-mesh enroll token is malformed")
    return token


def peer_path_for_deep_link(raw_url: str) -> str:
    """Map a supported `one-link://...` URL to a local UI path."""
    parsed = urlparse(str(raw_url or "").strip())
    if parsed.scheme != "one-link":
        raise ValueError("unsupported URL scheme")
    route = f"{parsed.netloc}{parsed.path}".strip("/")
    params = parse_qs(parsed.query, keep_blank_values=False)
    if route == "self-mesh/enroll":
        token = _validate_invite_token((params.get("token") or [""])[0])
        return "/peer?" + urlencode({"self_mesh_invite": token})
    raise ValueError(f"unsupported one-link route: {route or '<empty>'}")


def local_ui_url_for_deep_link(raw_url: str, *, port: int, token: str) -> str:
    path = peer_path_for_deep_link(raw_url)
    sep = "&" if "?" in path else "?"
    return f"http://127.0.0.1:{int(port)}{path}{sep}t={token}"


__all__ = [
    "local_ui_url_for_deep_link",
    "peer_path_for_deep_link",
]

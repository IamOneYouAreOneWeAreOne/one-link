"""GitHub Releases poll + version-compare for the in-app update banner.

Phase 2 of the production-install plan. Phase 1 ships native wheels to
GitHub Releases on every v* tag; this module is the read side that the
daemon uses to tell the UI "your build is older than the latest release
— click here to update."

Contract:
    * Pure functions. No global state, no async runtime requirements,
      no side effects beyond the single HTTPS GET when fetch_latest()
      runs. Easy to mock in tests.
    * Never raises on transient failure. A network outage / 403 rate
      limit / private repo returns CheckResult(status='unknown') so
      the UI silently does nothing instead of showing a scary error.
    * Cheap enough to call on every daemon startup. The HTTP call is
      one round-trip with a 4-second timeout; if it can't complete in
      that window, we give up.

The GitHub Releases REST endpoint is unauthenticated for public repos
(60 req/hr per IP). For private repos the daemon would need a token —
out of scope here; the repo will be public by the time end users hit
this code path.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

log = logging.getLogger("one_link.update_check")


# Default repo coordinates. Override via the explicit `repo` arg to
# fetch_latest() in tests / forks. Hard-coded here so the daemon doesn't
# need a config file just to point at a different fork.
DEFAULT_OWNER = "Jphilbrick10"
DEFAULT_REPO = "one-link"
DEFAULT_TIMEOUT_SECONDS = 4.0


@dataclass
class ReleaseInfo:
    """A subset of the GitHub Releases payload we care about. Anything
    the UI banner wants to display goes through here; raw GitHub JSON
    never leaks past this module."""

    tag: str                 # e.g. "v0.21.0"
    name: str                # human title (release notes header)
    html_url: str            # release page on GitHub
    published_at: str        # ISO-8601
    body: str = ""           # markdown release notes (truncated by caller if needed)
    prerelease: bool = False
    draft: bool = False
    asset_count: int = 0


@dataclass
class CheckResult:
    """What /api/update/check returns to the UI. status is the user-
    facing summary; everything else is detail the banner uses."""

    status: str              # 'newer' | 'same' | 'older' | 'unknown'
    local_version: str
    latest_version: Optional[str] = None
    latest: Optional[ReleaseInfo] = None
    error: Optional[str] = None  # short reason when status='unknown'

    def to_dict(self) -> dict:
        d = asdict(self)
        # Surface release URL/notes as top-level for UI ergonomics.
        if self.latest:
            d["latest_url"] = self.latest.html_url
            d["latest_published_at"] = self.latest.published_at
        return d


# ─── version parse + compare ───────────────────────────────────────────

_VERSION_RE = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:[-.]?(?P<pre>[a-zA-Z][\w.]*))?$"
)


def _parse_version(s: str) -> Optional[tuple]:
    """Parse a 'v0.21.0' / '0.21.0-alpha' / '0.21.0a1' style string into
    a comparable tuple. Returns None if the input doesn't match.

    Comparison rule: (major, minor, patch, pre_order). A release with
    no pre-release segment beats every pre-release at the same triple
    — Python's tuple ordering does the work as long as we put the
    'has-pre' bit BEFORE the pre identifier itself.

        0.21.0       -> (0, 21, 0, 1, '')      # 1 = is-release
        0.21.0-alpha -> (0, 21, 0, 0, 'alpha') # 0 = is-pre
        0.21.0a1     -> (0, 21, 0, 0, 'a1')

    'alpha' < 'a1' alphabetically; we don't try to be cleverer than
    that. Matches what packaging.Version does in practice.
    """
    if not s:
        return None
    m = _VERSION_RE.match(s.strip())
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3))
    pre = m.group("pre")
    if pre is None:
        return (major, minor, patch, 1, "")
    return (major, minor, patch, 0, pre.lower())


def compare_versions(local: str, remote: str) -> str:
    """Return one of 'newer' (remote > local), 'same', 'older' (remote
    < local), or 'unknown' if either side fails to parse. The UI uses
    this to decide whether to show the update banner."""
    lt = _parse_version(local)
    rt = _parse_version(remote)
    if lt is None or rt is None:
        return "unknown"
    if rt > lt:
        return "newer"
    if rt < lt:
        return "older"
    return "same"


# ─── HTTP fetch ────────────────────────────────────────────────────────

def _build_url(owner: str, repo: str) -> str:
    return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"


# Type alias for the fetch hook — lets tests inject a fake without
# touching urllib.
FetchFn = Callable[[str, float], dict]


def _default_fetch(url: str, timeout: float) -> dict:
    """One synchronous HTTPS GET to the GitHub Releases API. Returns
    the parsed JSON body. Raises urllib.error.URLError / HTTPError /
    json.JSONDecodeError on failure — the public fetch_latest()
    wraps those into a clean unknown-status response."""
    req = urllib.request.Request(
        url,
        headers={
            # Identify the daemon so a future GitHub API change /
            # rate-limit policy can pick us out from generic curl
            # traffic. No secrets in this header.
            "User-Agent": "one-link-update-check/0.21",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        if resp.status != 200:
            raise urllib.error.HTTPError(
                url, resp.status, resp.reason, resp.headers, None
            )
        return json.loads(resp.read().decode("utf-8"))


def fetch_latest(
    local_version: str,
    *,
    owner: str = DEFAULT_OWNER,
    repo: str = DEFAULT_REPO,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    fetch: FetchFn = _default_fetch,
) -> CheckResult:
    """Look up the latest GitHub Release for `owner/repo` and compare
    its tag to `local_version`. Always returns a CheckResult — never
    raises. Pass a `fetch` callable to mock the HTTP layer in tests.
    """
    url = _build_url(owner, repo)
    try:
        payload = fetch(url, timeout)
    except urllib.error.HTTPError as e:
        # 404 = repo has no published releases yet (common during
        # initial setup); treat as 'unknown' so the UI stays quiet.
        log.info(
            "update_check: GitHub returned HTTP %s for %s (%s)",
            e.code, url, e.reason,
        )
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error=f"http {e.code}",
        )
    except urllib.error.URLError as e:
        # Offline / DNS failure / TLS handshake issue.
        log.info("update_check: network failure fetching %s: %s", url, e)
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error=f"network: {e.reason if hasattr(e, 'reason') else e}",
        )
    except (json.JSONDecodeError, TimeoutError) as e:
        log.info("update_check: bad/late response from %s: %s", url, e)
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error=f"parse: {e}",
        )

    tag = (payload.get("tag_name") or "").strip()
    if not tag:
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error="no tag_name in latest release",
        )

    info = ReleaseInfo(
        tag=tag,
        name=payload.get("name") or tag,
        html_url=payload.get("html_url") or "",
        published_at=payload.get("published_at") or "",
        body=payload.get("body") or "",
        prerelease=bool(payload.get("prerelease")),
        draft=bool(payload.get("draft")),
        asset_count=len(payload.get("assets") or []),
    )

    return CheckResult(
        status=compare_versions(local_version, tag),
        local_version=local_version,
        latest_version=tag,
        latest=info,
    )

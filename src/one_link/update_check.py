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
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Callable, Optional

from packaging.version import InvalidVersion, Version

from one_link.safe_http import validated_urlopen

log = logging.getLogger("one_link.update_check")


# Default repo coordinates. Override via the explicit `repo` arg to
# fetch_latest() in tests / forks. Hard-coded here so the daemon doesn't
# need a config file just to point at a different fork.
DEFAULT_OWNER = "IamOneYouAreOneWeAreOne"
DEFAULT_REPO = "one-link"
DEFAULT_TIMEOUT_SECONDS = 4.0
MAX_RELEASE_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RELEASE_NOTES_CHARS = 64 * 1024
_REPO_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")

# The rolling prerelease every /download/* route resolves to.
ROLLING_TAG = "auto-latest"

# A rolling release has no version to compare -- its tag never changes. Its
# identity is the commit it was built from, which the publisher writes into the
# release title and body ("Rolling build (master <sha>)").
_COMMIT_RE = re.compile(r"\b([0-9a-f]{40})\b")


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
    # Rolling-channel identity. A rolling tag never changes, so the comparison
    # is between build commits rather than versions.
    local_commit: str = ""
    latest_commit: str = ""
    channel: str = "release"     # 'release' | 'rolling'
    # Whether THIS newer build can be installed in-place by the authenticated
    # external helper. The pure checker cannot know the runtime, and a rolling
    # build can never self-install -- continuous builds deliberately hold no
    # release authority; only tagged, Sigstore-signed releases do. The server
    # overlays True exactly when the newer build is a tagged release AND this
    # exact process proved the external-helper capability.
    can_self_install: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        # Surface release URL/notes as top-level for UI ergonomics.
        if self.latest:
            d["latest_url"] = self.latest.html_url
            d["latest_published_at"] = self.latest.published_at
        # Say what the user should DO. The server upgrades this to an in-app
        # install exactly when the runtime proves it can perform one.
        if self.status == "newer":
            d["action"] = "download"
            d["action_url"] = "https://weareone-link.org/download/"
            if self.channel == "rolling":
                d["action_note"] = (
                    "A newer build is published. Rolling builds are refreshed "
                    "by downloading and reinstalling; only tagged, "
                    "Sigstore-signed releases carry in-app install authority."
                )
            else:
                d["action_note"] = (
                    "A newer release is published. Download and reinstall "
                    "to get it."
                )
        return d


# ─── version parse + compare ───────────────────────────────────────────

def _parse_version(s: str) -> Optional[Version]:
    """Parse one bounded PEP 440 version without ever raising.

    Update ordering is a release-integrity decision: lexical prerelease
    comparison gets values such as ``rc10`` versus ``rc2`` wrong.  Use the
    packaging reference implementation so alpha/beta/RC/dev/post/local forms
    have deterministic, standards-compliant ordering.
    """

    if not isinstance(s, str):
        return None
    candidate = s.strip()
    if not candidate or len(candidate) > 128:
        return None
    try:
        return Version(candidate)
    except InvalidVersion:
        return None


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

def _validate_repo(owner: str, repo: str) -> None:
    if not _REPO_COMPONENT_RE.fullmatch(str(owner)):
        raise ValueError("invalid update repository owner")
    if not _REPO_COMPONENT_RE.fullmatch(str(repo)):
        raise ValueError("invalid update repository name")


def _build_url(owner: str, repo: str) -> str:
    _validate_repo(owner, repo)
    return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"


def _build_rolling_url(owner: str, repo: str, tag: str = ROLLING_TAG) -> str:
    """The rolling channel, which ``releases/latest`` cannot see.

    ``/releases/latest`` EXCLUDES prereleases by definition. The rolling channel
    is published as a prerelease on purpose, and it is the only release this
    project has ever cut, so that endpoint returns a bare 404:

        {"message": "Not Found", "status": "404"}

    fetch_latest turned that into status='unknown' and the UI stayed silent, so
    an installed build could not discover it was months behind -- including
    behind fixes for a startup crash. Asking for the tag directly is the only
    way to see the channel users actually download from.
    """

    _validate_repo(owner, repo)
    return (
        f"https://api.github.com/repos/{owner}/{repo}/releases/tags/"
        f"{urllib.parse.quote(tag, safe='')}"
    )


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
    with validated_urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise urllib.error.HTTPError(
                url, resp.status, resp.reason, resp.headers, None
            )
        raw = resp.read(MAX_RELEASE_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RELEASE_RESPONSE_BYTES:
            raise ValueError("GitHub release response exceeds 2 MiB")
        return json.loads(raw.decode("utf-8", "strict"))


def release_commit(payload: dict) -> str:
    """The 40-hex commit a rolling release was built from, or "".

    Read from the title first and the notes second, because the publisher writes
    it into both and the title is the shorter, less forgeable surface. Never
    guesses: without a commit the caller must report 'unknown', not 'newer'.
    """

    for key in ("name", "body"):
        value = payload.get(key)
        if not isinstance(value, str):
            continue
        match = _COMMIT_RE.search(value.lower())
        if match:
            return match.group(1)
    return ""


def compare_rolling(local_commit: str, remote_commit: str) -> str:
    """Rolling channel status from commits alone.

    There is no ordering here and none is invented: two different commits mean
    "the published build is not the one you are running", which for a channel
    that only ever moves forward is what a user needs to know. An unknown local
    commit -- a source checkout, or an artifact built before stamping existed --
    yields 'unknown' so a developer is never nagged and no false claim is made.
    """

    if not local_commit or not remote_commit:
        return "unknown"
    return "same" if local_commit == remote_commit else "newer"


def fetch_rolling(
    local_version: str,
    *,
    local_commit: str = "",
    owner: str = DEFAULT_OWNER,
    repo: str = DEFAULT_REPO,
    tag: str = ROLLING_TAG,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    fetch: FetchFn = _default_fetch,
) -> CheckResult:
    """Check the rolling prerelease channel. Never raises."""

    url = ""
    try:
        url = _build_rolling_url(owner, repo, tag)
        payload = fetch(url, timeout)
    except urllib.error.HTTPError as e:
        log.info("update_check: rolling channel HTTP %s for %s", e.code, url)
        return CheckResult(
            status="unknown", local_version=local_version, error=f"http {e.code}"
        )
    except urllib.error.URLError as e:
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error=f"network: {getattr(e, 'reason', e)}",
        )
    except (json.JSONDecodeError, TimeoutError, UnicodeError, ValueError) as e:
        return CheckResult(
            status="unknown", local_version=local_version, error=f"parse: {e}"
        )
    except Exception as e:
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error=f"fetch: {type(e).__name__}",
        )

    if not isinstance(payload, dict):
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error="rolling release payload is not an object",
        )
    remote_commit = release_commit(payload)
    if not remote_commit:
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error="rolling release does not record a build commit",
        )

    assets = payload.get("assets")
    if not isinstance(assets, list) or len(assets) > 5_000:
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error="malformed or excessive release assets",
        )

    def _bounded_text(value: object, limit: int) -> str:
        return value[:limit] if isinstance(value, str) else ""

    tag_value = payload.get("tag_name")
    resolved_tag = tag_value.strip() if isinstance(tag_value, str) else tag
    if not resolved_tag or len(resolved_tag) > 128:
        resolved_tag = tag

    info = ReleaseInfo(
        tag=resolved_tag,
        name=_bounded_text(payload.get("name"), 512) or resolved_tag,
        html_url=(
            f"https://github.com/{owner}/{repo}/releases/tag/"
            f"{urllib.parse.quote(resolved_tag, safe='')}"
        ),
        published_at=_bounded_text(payload.get("published_at"), 64),
        body=_bounded_text(payload.get("body"), MAX_RELEASE_NOTES_CHARS),
        prerelease=bool(payload.get("prerelease")),
        draft=bool(payload.get("draft")),
        asset_count=len(assets),
    )
    return CheckResult(
        status=compare_rolling(local_commit, remote_commit),
        local_version=local_version,
        latest_version=resolved_tag,
        latest=info,
        local_commit=local_commit,
        latest_commit=remote_commit,
        channel="rolling",
    )


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
    url = ""
    try:
        url = _build_url(owner, repo)
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
    except (json.JSONDecodeError, TimeoutError, UnicodeError, ValueError) as e:
        log.info("update_check: bad/late response from %s: %s", url, e)
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error=f"parse: {e}",
        )
    except Exception as e:
        log.info("update_check: unexpected fetch failure: %s", e)
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error=f"fetch: {type(e).__name__}",
        )

    if not isinstance(payload, dict):
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error="latest release payload is not an object",
        )
    tag_value = payload.get("tag_name")
    tag = tag_value.strip() if isinstance(tag_value, str) else ""
    if not tag or len(tag) > 128 or _parse_version(tag) is None:
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error="missing or invalid tag_name in latest release",
        )

    assets = payload.get("assets")
    if not isinstance(assets, list) or len(assets) > 5_000:
        return CheckResult(
            status="unknown",
            local_version=local_version,
            error="malformed or excessive release assets",
        )

    def _bounded_text(value: object, limit: int) -> str:
        return value[:limit] if isinstance(value, str) else ""

    release_url = (
        f"https://github.com/{owner}/{repo}/releases/tag/"
        f"{urllib.parse.quote(tag, safe='')}"
    )

    info = ReleaseInfo(
        tag=tag,
        name=_bounded_text(payload.get("name"), 512) or tag,
        html_url=release_url,
        published_at=_bounded_text(payload.get("published_at"), 64),
        body=_bounded_text(payload.get("body"), MAX_RELEASE_NOTES_CHARS),
        prerelease=bool(payload.get("prerelease")),
        draft=bool(payload.get("draft")),
        asset_count=len(assets),
    )

    return CheckResult(
        status=compare_versions(local_version, tag),
        local_version=local_version,
        latest_version=tag,
        latest=info,
    )


def check_for_update(
    local_version: str | None = None,
    *,
    local_commit: str | None = None,
    owner: str = DEFAULT_OWNER,
    repo: str = DEFAULT_REPO,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    fetch: FetchFn = _default_fetch,
) -> CheckResult:
    """The one call a caller should make: "am I running the newest build?"

    Tries the tagged-release channel first and falls back to the rolling
    prerelease, because today there IS no tagged release -- ``releases/latest``
    404s -- and the rolling prerelease is what every /download/* route serves.
    Preferring the tagged channel means this needs no change on the day
    release.yml finally cuts one.

    Falls back only when the tagged channel yields nothing usable, never to
    downgrade a real answer: a tagged release that says 'same' or 'older' is the
    authoritative verdict and is returned as-is.
    """

    if local_version is None:
        from one_link import __version__ as local_version_default

        local_version = local_version_default
    if local_commit is None:
        from one_link.build_info import build_commit

        local_commit = build_commit()

    tagged = fetch_latest(
        local_version, owner=owner, repo=repo, timeout=timeout, fetch=fetch
    )
    if tagged.status != "unknown":
        return tagged

    rolling = fetch_rolling(
        local_version,
        local_commit=local_commit,
        owner=owner,
        repo=repo,
        timeout=timeout,
        fetch=fetch,
    )
    if rolling.status != "unknown":
        return rolling
    # Both unknown: report the rolling reason, since that is the channel a user
    # actually downloads from, but keep the tagged error when rolling had none.
    return CheckResult(
        status="unknown",
        local_version=local_version,
        local_commit=local_commit,
        channel="rolling",
        error=rolling.error or tagged.error,
    )

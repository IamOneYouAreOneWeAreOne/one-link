from __future__ import annotations

import urllib.request
import urllib.error

import pytest

from one_link.safe_http import validated_urlopen


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeOpener:
    def __init__(self, seen):
        self.seen = seen

    def open(self, request, *, timeout):
        self.seen["url"] = (
            request.full_url if isinstance(request, urllib.request.Request) else request
        )
        self.seen["timeout"] = timeout
        return _FakeResponse()


def _capture_opener(monkeypatch, seen):
    def fake_build_opener(*handlers):
        seen["handlers"] = handlers
        return _FakeOpener(seen)

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)


def test_validated_urlopen_allows_https(monkeypatch):
    seen = {}

    _capture_opener(monkeypatch, seen)
    req = urllib.request.Request("https://example.test/releases/latest")

    with validated_urlopen(req, timeout=3.0):
        pass

    assert seen["url"] == "https://example.test/releases/latest"
    assert seen["timeout"] == 3.0
    assert len(seen["handlers"]) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:7117/api/status",
        "http://localhost:7117/api/status",
        "http://[::1]:7117/api/status",
    ],
)
def test_validated_urlopen_allows_loopback_http_when_requested(monkeypatch, url):
    _capture_opener(monkeypatch, {})
    with validated_urlopen(url, timeout=1.0, allow_loopback_http=True):
        pass


@pytest.mark.parametrize(
    "url",
    [
        "file:///$HOME/secret.txt",
        "ftp://example.test/file",
        "http://192.168.1.50:7117/api/status",
        "http://example.test/api/status",
        "https://localhost/admin",
        "https://127.0.0.1/admin",
        "https://127.1/admin",
        "https://10.1.2.3/admin",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/admin",
        "https://[fe80::1]/admin",
        "https://user:password@example.test/path",
    ],
)
def test_validated_urlopen_rejects_unexpected_schemes_and_hosts(monkeypatch, url):
    def fake_build_opener(*args, **kwargs):
        raise AssertionError("opener should not be built for rejected URLs")

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    with pytest.raises(ValueError, match="refusing URL"):
        validated_urlopen(url, timeout=1.0, allow_loopback_http=True)


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:7117/api/status",
        "http://192.168.1.50/admin",
        "https://localhost/admin",
        "https://10.0.0.1/admin",
        "https://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "ftp://example.test/archive",
    ],
)
def test_https_fetch_revalidates_and_rejects_unsafe_redirects(target):
    from one_link.safe_http import _ValidatedRedirectHandler

    handler = _ValidatedRedirectHandler(
        allow_https=True,
        allow_loopback_http=False,
    )
    request = urllib.request.Request("https://example.test/releases/latest")
    with pytest.raises(ValueError, match="refusing URL"):
        handler.redirect_request(request, None, 302, "Found", {}, target)


def test_loopback_client_redirect_cannot_escape_to_lan():
    from one_link.safe_http import _ValidatedRedirectHandler

    handler = _ValidatedRedirectHandler(
        allow_https=True,
        allow_loopback_http=True,
    )
    request = urllib.request.Request("http://127.0.0.1:7117/api/status")
    with pytest.raises(ValueError, match="refusing URL"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "http://192.168.1.50/admin",
        )


def test_https_fetch_allows_relative_same_origin_redirect():
    from one_link.safe_http import _ValidatedRedirectHandler

    handler = _ValidatedRedirectHandler(
        allow_https=True,
        allow_loopback_http=False,
    )
    request = urllib.request.Request("https://example.test/releases/latest")
    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "../assets/package.whl",
    )
    assert redirected is not None
    assert redirected.full_url == "https://example.test/assets/package.whl"


def test_https_fetch_rejects_scheme_downgrade():
    from one_link.safe_http import _ValidatedRedirectHandler

    handler = _ValidatedRedirectHandler(
        allow_https=True,
        allow_loopback_http=False,
    )
    request = urllib.request.Request("https://example.test/releases/latest")
    with pytest.raises(ValueError, match="refusing URL"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "http://example.test/package.whl",
        )


def test_redirect_chain_has_independent_hard_limit():
    from one_link.safe_http import MAX_HTTP_REDIRECTS, _ValidatedRedirectHandler

    handler = _ValidatedRedirectHandler(
        allow_https=True,
        allow_loopback_http=False,
    )
    request = urllib.request.Request("https://example.test/start")
    for index in range(MAX_HTTP_REDIRECTS):
        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            f"/hop/{index}",
        )
        assert redirected is not None
        request = redirected
    with pytest.raises(urllib.error.HTTPError, match="redirect limit exceeded"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "/loop",
        )

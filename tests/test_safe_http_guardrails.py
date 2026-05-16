from __future__ import annotations

import urllib.request

import pytest

from one_link.safe_http import validated_urlopen


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_validated_urlopen_allows_https(monkeypatch):
    seen = {}

    def fake_urlopen(request, *, timeout, **kwargs):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        return _FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    req = urllib.request.Request("https://example.test/releases/latest")

    with validated_urlopen(req, timeout=3.0):
        pass

    assert seen == {"url": "https://example.test/releases/latest", "timeout": 3.0}


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:7117/api/status",
        "http://localhost:7117/api/status",
        "http://[::1]:7117/api/status",
    ],
)
def test_validated_urlopen_allows_loopback_http_when_requested(monkeypatch, url):
    def fake_urlopen(request, *, timeout, **kwargs):
        return _FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with validated_urlopen(url, timeout=1.0, allow_loopback_http=True):
        pass


@pytest.mark.parametrize(
    "url",
    [
        "file:///$HOME/secret.txt",
        "ftp://example.test/file",
        "http://192.168.1.50:7117/api/status",
        "http://example.test/api/status",
    ],
)
def test_validated_urlopen_rejects_unexpected_schemes_and_hosts(monkeypatch, url):
    def fake_urlopen(*args, **kwargs):
        raise AssertionError("urlopen should not be reached for rejected URLs")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ValueError, match="refusing URL"):
        validated_urlopen(url, timeout=1.0, allow_loopback_http=True)

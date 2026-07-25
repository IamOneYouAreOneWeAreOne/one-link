"""2026-06-16 (external-audit XSS hardening): the main UI CSP must use a
HASH-based script-src with NO 'unsafe-inline', so a future injected
inline <script>/on*= handler cannot execute. This pins the contract at
the HTTP layer (header <-> served-body consistency), without needing a
browser; the playwright e2e suite covers actual in-browser execution.
"""
from __future__ import annotations

import base64
import hashlib
import re

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="csp-host",
    )


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(_identity())
    daemon.state = state
    daemon.discovery = None
    server = UIServer(daemon)
    ts = TestServer(server.app)
    c = TestClient(ts)
    await c.start_server()
    try:
        yield c, server.token
    finally:
        await c.close()
        state.close()


def _csp(resp) -> str:
    return resp.headers.get("Content-Security-Policy", "")


def _script_src(csp: str) -> str:
    for directive in csp.split(";"):
        directive = directive.strip()
        if directive.startswith("script-src"):
            return directive
    return ""


@pytest.mark.asyncio
async def test_index_csp_script_src_has_no_unsafe_inline(client):
    c, token = client
    resp = await c.get(f"/?t={token}")
    assert resp.status == 200
    csp = _csp(resp)
    assert csp, "main UI must set a Content-Security-Policy"
    ss = _script_src(csp)
    assert ss, "CSP must declare script-src"
    assert "'unsafe-inline'" not in ss, (
        "script-src must NOT allow 'unsafe-inline' — that's the whole "
        "point of the hash-based CSP (a future injected inline script "
        "must not execute)"
    )
    assert "'unsafe-eval'" not in ss and "'wasm-unsafe-eval'" not in ss, (
        "script-src must not allow eval / wasm-eval (WASM is unused in the UI)"
    )


@pytest.mark.asyncio
async def test_index_csp_hashes_match_every_inline_script(client):
    """Every inline <script> in the served body must have a matching
    'sha256-...' in script-src. If they don't match byte-for-byte, the
    browser blocks the script and the UI white-screens — so this is the
    load-bearing correctness check for the hardening."""
    c, token = client
    resp = await c.get(f"/?t={token}")
    body = await resp.text()
    ss = _script_src(_csp(resp))
    csp_hashes = set(re.findall(r"'sha256-([A-Za-z0-9+/=]+)'", ss))
    assert csp_hashes, "script-src must list sha256 hashes for inline scripts"

    blocks = re.findall(r"<script\b[^>]*>(.*?)</script>", body, re.DOTALL)
    assert blocks, "served index must contain inline <script> blocks"
    # The bootstrap scrub script is injected on the ?t= path, so there
    # should be at least the 2 bundled blocks + the scrub.
    assert len(blocks) >= 2
    for block in blocks:
        h = base64.b64encode(
            hashlib.sha256(block.encode("utf-8")).digest()
        ).decode("ascii")
        assert h in csp_hashes, (
            "an inline <script> in the body has no matching sha256 in "
            "the CSP — the browser would block it (white screen)"
        )


@pytest.mark.asyncio
async def test_index_csp_keeps_style_src_inline(client):
    """Inline style="" attrs (189 of them) are a far weaker vector and
    aren't hashed; style-src must keep 'unsafe-inline' so the UI renders."""
    c, token = client
    resp = await c.get(f"/?t={token}")
    csp = _csp(resp)
    style = next(
        (d.strip() for d in csp.split(";") if d.strip().startswith("style-src")),
        "",
    )
    assert "'unsafe-inline'" in style


@pytest.mark.asyncio
async def test_index_304_carries_same_csp(client):
    """A conditional GET (If-None-Match) must still carry the CSP so the
    reused cached body is enforced."""
    c, _token = client
    first = await c.get("/")
    etag = first.headers.get("ETag")
    assert etag
    second = await c.get("/", headers={"If-None-Match": etag})
    assert second.status == 304
    assert "script-src" in _csp(second)

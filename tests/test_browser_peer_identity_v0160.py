"""v0.16.0 — Browser-as-peer: identity layer.

First ship of the v0.16-0.19 phone-as-peer architecture. Browser
generates its own Ed25519 keypair via Web Crypto, persists it in
OPFS, computes a fingerprint. The browser is its own One Link
node — separate from any daemon, with its own identity, its own
storage, its own peers (peers + WebRTC arrive in subsequent ships).

  Reach:  a phone that opens /peer becomes its own One Link node
          instead of a remote control for a desktop daemon. No
          account, no cloud, no daemon required on phone.
  Hide:   the route is unauthenticated by design — auth happens
          peer-to-peer via the keypair, not via the daemon's UI
          token. Browsers without OPFS or Ed25519 see a clear
          error message instead of a silent broken state.
  Async:  identity load + generation are async (Web Crypto +
          OPFS). The boot path is "load if exists; else
          generate; else surface error" — never a partial state.
  Depth:  fingerprint is algorithm-tagged (`sha256:<hex>`) so a
          future ship can vendor BLAKE3-WASM and produce
          daemon-compatible fingerprints without breaking
          backward compatibility on already-provisioned browser
          identities.

Tests: route shape, CSP, peer.html structure, JS module
contracts, fingerprint algorithm pin.
"""

from __future__ import annotations

from pathlib import Path

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
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="peer-host",
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()
        state.close()


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


# ───────── route + transport ────────────────────────────────────────

@pytest.mark.asyncio
async def test_peer_route_unauthenticated(http):
    """The /peer route MUST be reachable without the daemon's UI
    token. The browser-peer page authenticates itself via its own
    keypair, not via the daemon's auth gate."""
    client = http
    resp = await client.get("/peer")
    assert resp.status == 200
    body = await resp.text()
    assert "<html" in body.lower()


@pytest.mark.asyncio
async def test_peer_route_with_trailing_slash(http):
    """Both /peer and /peer/ MUST work — trailing-slash drift is a
    common URL-bar typing quirk; redirect or alias is fine, but
    don't 404."""
    client = http
    resp = await client.get("/peer/")
    assert resp.status == 200


@pytest.mark.asyncio
async def test_peer_route_serves_html(http):
    """Content-Type MUST be text/html so the browser parses + runs
    the inline script."""
    client = http
    resp = await client.get("/peer")
    ct = resp.headers.get("Content-Type", "")
    assert "text/html" in ct


@pytest.mark.asyncio
async def test_peer_route_csp_locks_third_party_scripts(http):
    """The peer page MUST have a tight CSP — script-src 'self' only,
    no third-party. Any future ship that wants to vendor a JS
    library (BLAKE3-WASM, QR encoder) MUST inline it; CSP is the
    enforcement floor."""
    client = http
    resp = await client.get("/peer")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    # Connections are allowed to wss/https because v0.17.0 will
    # register with rendezvous (WSS) and v0.18.0 will signal via
    # rendezvous; pin those allowances now so future ships don't
    # have to relax CSP from scratch.
    assert "connect-src" in csp
    assert "wss:" in csp


# ───────── markup contract ──────────────────────────────────────────

def test_peer_html_renders_at_phone_widths(peer_html: str):
    """The viewport meta MUST include `viewport-fit=cover` so the
    page paints under the iPhone home indicator instead of leaving
    a black band."""
    assert 'name="viewport"' in peer_html
    assert "viewport-fit=cover" in peer_html


def test_peer_html_includes_manifest_link(peer_html: str):
    """The peer shell MUST be installable as a PWA — same
    manifest as the daemon UI, but the page itself is the peer
    runtime."""
    assert '<link rel="manifest" href="/manifest.json"' in peer_html


def test_peer_html_uses_safe_area_insets(peer_html: str):
    """env(safe-area-inset-*) padding MUST be applied so the layout
    respects iPhone home indicator + notch on standalone PWA install."""
    assert "env(safe-area-inset-top)" in peer_html
    assert "env(safe-area-inset-bottom)" in peer_html


def test_peer_html_has_identity_card(peer_html: str):
    """The identity card MUST exist — that's the v0.16.0 surface."""
    assert 'id="identity-card"' in peer_html
    assert 'id="ident-fp"' in peer_html
    assert 'id="ident-pub"' in peer_html
    assert 'id="ident-state"' in peer_html


def test_peer_html_has_actions_card(peer_html: str):
    """Reset + Export are the two minimum identity-management
    affordances. Without Reset, a corrupted identity blocks the
    user; without Export, identity isn't portable."""
    assert 'id="btn-reset"' in peer_html
    assert 'id="btn-export"' in peer_html


# ───────── JS module contract ───────────────────────────────────────

def test_js_exposes_test_surface(peer_html: str):
    """The peer JS MUST expose a stable `window.__oneLinkPeer`
    surface so future tests + interop ships can call into it
    without parsing the inline script."""
    assert "window.__oneLinkPeer" in peer_html
    # The surface MUST include the canonical primitives.
    for name in (
        "fingerprintOf",
        "readIdentity",
        "writeIdentity",
        "deleteIdentity",
        "generateIdentity",
        "bytesToHex",
        "bytesToB64Url",
        "b64UrlToBytes",
    ):
        assert name in peer_html, f"peer.html missing {name}"


def test_js_uses_web_crypto_ed25519(peer_html: str):
    """Identity MUST be generated via Web Crypto's native Ed25519,
    not a vendored library. Vendored crypto is a sovereignty +
    audit-surface concern; native Web Crypto is the floor."""
    idx = peer_html.find("function generateIdentity")
    snippet = peer_html[idx:idx + 2000]
    assert 'crypto.subtle.generateKey' in snippet
    assert '"Ed25519"' in snippet or "'Ed25519'" in snippet


def test_js_handles_spki_and_raw_ed25519(peer_html: str):
    """Browsers vary on whether crypto.subtle.exportKey('raw') works
    for Ed25519 (Chrome 113+ does; Safari 17 takes 'spki'). The
    code MUST handle both — extract 32-byte raw OR strip ASN.1
    SPKI prefix."""
    idx = peer_html.find("function generateIdentity")
    snippet = peer_html[idx:idx + 2000]
    assert "byteLength === 32" in snippet
    assert ".slice(-32)" in snippet


def test_js_persists_to_opfs(peer_html: str):
    """Identity persistence MUST go through OPFS (origin-private
    filesystem), not localStorage / IndexedDB plain. OPFS is the
    only browser storage that survives `clear cookies` and isn't
    accessible to other tabs from the same origin if the user is
    in incognito."""
    assert "navigator.storage.getDirectory()" in peer_html
    assert "getFileHandle" in peer_html
    assert "createWritable" in peer_html


def test_js_identity_layout_pinned(peer_html: str):
    """The OPFS layout `identity/v1/keypair.json` is the wire
    contract for any ship that reads/writes identity. Pin it so
    a refactor to `identity/v2/...` is an explicit migration."""
    assert "identity" in peer_html
    assert "v1" in peer_html
    assert "keypair.json" in peer_html


# ───────── fingerprint contract ─────────────────────────────────────

def test_js_fingerprint_uses_sha256_with_algo_tag(peer_html: str):
    """Browser fingerprints are tagged `sha256:<hex>` so a future
    ship that vendors BLAKE3-WASM can produce `blake3:<hex>` and
    coexist on the wire without ambiguity. Naked-hex fingerprints
    would be a forward-compat trap."""
    idx = peer_html.find("function fingerprintOf")
    snippet = peer_html[idx:idx + 600]
    assert '"SHA-256"' in snippet
    assert '"sha256:"' in snippet


def test_js_clear_quickfail_for_missing_features(peer_html: str):
    """If the browser doesn't have Web Crypto or OPFS, the user
    MUST see a clear "your browser doesn't support X, try Y"
    message — not a silent broken state."""
    assert "no web crypto" in peer_html.lower() or "no-web-crypto" in peer_html
    assert "no opfs" in peer_html.lower() or "no-opfs" in peer_html


# ───────── reset + export wiring ────────────────────────────────────

def test_js_reset_confirms_destructive_action(peer_html: str):
    """The reset path MUST require explicit confirmation. Identity
    loss is unrecoverable; a stray click can't blow it up."""
    idx = peer_html.find('"#btn-reset"')
    snippet = peer_html[idx:idx + 800]
    assert "confirm(" in snippet
    assert "Reset" in snippet
    assert "There's no undo" in snippet or "no undo" in snippet


def test_js_export_writes_json_blob(peer_html: str):
    """Export MUST produce a downloadable JSON blob — not a copy-
    to-clipboard or DOM render. Identity backups are sensitive;
    they belong in a file the user can store in their own backup
    flow, not in clipboard history."""
    idx = peer_html.find('"#btn-export"')
    snippet = peer_html[idx:idx + 1200]
    assert "Blob([" in snippet or "new Blob" in snippet
    assert "application/json" in snippet
    assert ".click()" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_peer_html_version_pin(peer_html: str):
    """The peer JS surface MUST advertise a version string so a
    future ship can detect upgrades + run migrations. Forward-compat:
    pin the SHAPE (string with semver-ish content) not a literal."""
    import re

    m = re.search(r"version:\s*['\"]\d+\.\d+\.\d+['\"]", peer_html)
    assert m, "peer.html __oneLinkPeer.version must be a quoted semver"


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

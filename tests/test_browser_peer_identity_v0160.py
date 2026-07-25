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

import hashlib
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
    assert "worker-src 'self'" in csp
    script_directive = next(
        directive.strip()
        for directive in csp.split(";")
        if directive.strip().startswith("script-src ")
    )
    assert "'wasm-unsafe-eval'" in script_directive.split()
    assert "'unsafe-eval'" not in script_directive.split()
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp


@pytest.mark.asyncio
async def test_peer_route_revalidation_repeats_security_policy(http):
    first = await http.get("/peer")
    assert first.status == 200
    etag = first.headers["ETag"]
    expected_csp = first.headers["Content-Security-Policy"]
    await first.read()
    second = await http.get("/peer", headers={"If-None-Match": etag})
    assert second.status == 304
    assert second.headers["Content-Security-Policy"] == expected_csp


@pytest.mark.asyncio
async def test_clean_owner_ui_reload_is_compressed(http):
    response = await http.get("/", headers={"Accept-Encoding": "gzip"})
    assert response.status == 200
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Cache-Control"] == "no-cache, must-revalidate"
    assert "One Link" in await response.text()


@pytest.mark.asyncio
async def test_browser_argon_worker_and_wasm_are_exact_no_store_assets(http):
    worker_response = await http.get("/browser-crypto/argon2id-worker.js")
    assert worker_response.status == 200
    assert worker_response.headers["Content-Type"].startswith(
        "application/javascript"
    )
    assert worker_response.headers["Cache-Control"] == "no-store, max-age=0"
    assert worker_response.headers["X-Content-Type-Options"] == "nosniff"
    assert worker_response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    worker = await worker_response.text()

    wasm_response = await http.get("/browser-crypto/argon2id-v1.wasm")
    assert wasm_response.status == 200
    assert wasm_response.headers["Content-Type"].startswith("application/wasm")
    assert wasm_response.headers["Cache-Control"] == "no-store, max-age=0"
    assert wasm_response.headers["X-Content-Type-Options"] == "nosniff"
    wasm = await wasm_response.read()
    assert wasm.startswith(b"\x00asm")
    assert 8 <= len(wasm) <= 128 * 1024
    digest = hashlib.sha256(wasm).hexdigest()
    assert digest == "8fac36bd917280333cd7ca4bcc262b1733ed120035507008b09c0c3f1f172505"
    assert digest in worker


@pytest.mark.asyncio
async def test_browser_ed25519_wasm_is_exact_no_store_asset(http):
    response = await http.get("/browser-crypto/ed25519-v1.wasm")
    assert response.status == 200
    assert response.headers["Content-Type"].startswith("application/wasm")
    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    blob = await response.read()
    assert blob.startswith(b"\x00asm")
    assert 8 <= len(blob) <= 256 * 1024
    assert hashlib.sha256(blob).hexdigest() == (
        "99792408d50e1b920e99ab9e85095cf0f77f9933a30bcb81b63f7556b34f6cc0"
    )


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


def test_identity_read_distinguishes_absence_from_corruption(peer_html: str):
    """Only a real NotFoundError may authorize first-install key generation."""
    assert 'error.name === "NotFoundError"' in peer_html
    assert "class IdentityCorruptionError" in peer_html
    assert "keypair.json is not valid JSON" not in peer_html  # filename is dynamic
    read_idx = peer_html.find("async function _readIdentityUnlocked()")
    boot_idx = peer_html.find("async function _loadOrCreateIdentity()")
    assert read_idx >= 0 and boot_idx > read_idx
    read_snippet = peer_html[read_idx:boot_idx]
    assert 'current.status === "corrupt"' in read_snippet
    assert "throw current.error" in read_snippet


def test_identity_authority_is_crypto_validated_before_use(peer_html: str):
    """Schema presence alone cannot authorize a stored Ed25519 identity."""
    public_idx = peer_html.find("async function _validatePublicIdentityFields")
    idx = peer_html.find("async function validatePlainIdentityRecord(rec)")
    assert 0 <= public_idx < idx
    snippet = peer_html[public_idx:idx + 5000]
    assert "fingerprintOf(publicBytes)" in snippet
    assert 'crypto.subtle.importKey(\n          "jwk"' in snippet
    assert "crypto.subtle.sign" in snippet
    assert "crypto.subtle.verify" in snippet
    assert "_wasmEd25519PublicFromSeed(privateSeed)" in snippet
    assert "_wasmEd25519Sign(privateSeed, probe)" in snippet
    assert "_wasmEd25519Verify(publicBytes, signature, probe)" in snippet
    assert "private key does not match the stored public key" in snippet


def test_identity_writes_are_locked_staged_and_read_back(peer_html: str):
    """Cross-tab races and partial writes may not silently roll authority."""
    assert 'ID_PENDING_FILE = "keypair.pending.json"' in peer_html
    assert 'ID_LOCK_NAME = "one-link.browser-identity.v1"' in peer_html
    assert "navigator.locks.request" in peer_html
    idx = peer_html.find("async function _writeIdentityUnlocked(rec)")
    assert idx >= 0
    snippet = peer_html[idx:idx + 1200]
    assert "validateIdentityObject(rec)" in snippet
    assert "_writeIdentityFile(dir, ID_PENDING_FILE, serialized)" in snippet
    assert "_writeIdentityFile(dir, ID_FILE, serialized)" in snippet
    assert "_removePendingIdentity(dir)" in snippet
    assert "failed exact read-back verification" in peer_html


def test_corrupt_primary_never_auto_promotes_staged_key(peer_html: str):
    idx = peer_html.find("async function _readIdentityUnlocked()")
    assert idx >= 0
    snippet = peer_html[idx:idx + 2200]
    corrupt_idx = snippet.find('current.status === "corrupt"')
    recover_idx = snippet.find("_recoverPendingIdentity")
    assert 0 <= corrupt_idx < recover_idx
    assert "throw current.error" in snippet[corrupt_idx:recover_idx]


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
    idx = peer_html.find('$("#btn-reset")?.addEventListener')
    assert idx >= 0
    snippet = peer_html[idx:idx + 800]
    assert "confirm(" in snippet
    assert "Reset" in snippet
    assert "There's no undo" in snippet or "no undo" in snippet


def test_js_export_writes_json_blob(peer_html: str):
    """Export MUST produce a downloadable JSON blob — not a copy-
    to-clipboard or DOM render. Identity backups are sensitive;
    they belong in a file the user can store in their own backup
    flow, not in clipboard history."""
    idx = peer_html.find('$("#btn-export")?.addEventListener')
    assert idx >= 0
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

    m = re.search(r"version:\s*['\"]\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?['\"]", peer_html)
    assert m, "peer.html __oneLinkPeer.version must be a quoted semver"


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

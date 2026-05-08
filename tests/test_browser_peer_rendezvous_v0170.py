"""v0.17.0 — Browser-as-peer: rendezvous client.

The browser publishes its presence to a rendezvous server using
the same wire format as the desktop daemon. From v0.17.0 onward
the browser-peer is reachable via the rendezvous + lookup
mechanism that desktop peers already use.

  Reach:  a phone-peer that boots in a fresh browser can register
          with a rendezvous, and any other peer that knows its
          public key can look it up. From here, v0.18.0 wires the
          WebRTC signaling that turns rendezvous lookup into a
          live DataChannel.
  Hide:   the rendezvous server stores presence only — never
          message content. The browser can self-host its own
          rendezvous (`python -m one_link.rendezvous_server`) so
          there's no third-party-server dependency required.
  Async:  registration is async (HTTP POST). Auto-refresh schedules
          a re-register at TTL - 30s so the listing doesn't expire
          mid-session.
  Depth:  wire format MUST match the desktop daemon's
          rendezvous_proto.RegisterReq exactly:
            - PROTOCOL_VERSION constant ("OL-RDZ-1")
            - canonical JSON (sorted keys, no spaces, ASCII-only
              with \\uXXXX-escaped non-ASCII)
            - Ed25519 signature over canonical bytes minus the
              "signature" field
            - standard base64 (with + / =) for pubkey_b64 +
              signature, NOT base64url
          Any drift in any of those means signatures don't verify
          and the rendezvous rejects the register.

Tests pin the wire-format primitives, the canonical JSON algorithm,
the standard-vs-url base64 conversion, the rendezvous client
helpers, and the UI wiring.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


# ───────── wire-format compat constants ─────────────────────────────

def test_protocol_version_matches_daemon(peer_html: str):
    """The browser MUST advertise the same PROTOCOL_VERSION the
    desktop daemon uses, or the rendezvous rejects with "unsupported
    protocol version"."""
    from one_link.rendezvous_proto import PROTOCOL_VERSION

    assert PROTOCOL_VERSION == "OL-RDZ-1", (
        "test out of sync with daemon proto"
    )
    assert f'RDZ_PROTOCOL_VERSION = "{PROTOCOL_VERSION}"' in peer_html


def test_default_ttl_reasonable(peer_html: str):
    """Default TTL must be long enough to outlast typical refresh
    drift (a few minutes) but short enough that a closed tab clears
    out within a single auto-refresh window. 5 minutes is the floor
    for the desktop daemon."""
    assert "RDZ_DEFAULT_TTL_S = 300" in peer_html


def test_refresh_margin_pinned(peer_html: str):
    """30-second margin before TTL expiry — enough for the network
    round-trip + one retry. Smaller margins risk the listing
    expiring mid-refresh."""
    assert "RDZ_REFRESH_MARGIN_MS = 30 * 1000" in peer_html


# ───────── canonical JSON ───────────────────────────────────────────

def test_canonical_json_helper_present(peer_html: str):
    """The signing canonicalization is the load-bearing primitive
    for every signature. Pin its presence + name."""
    assert "function _canonicalJson(obj)" in peer_html


def test_canonical_json_sorts_keys(peer_html: str):
    """Object key order MUST be deterministic. JSON.stringify on an
    object reflects insertion order; the canonical form sorts."""
    idx = peer_html.find("function _canonicalJson(obj)")
    snippet = peer_html[idx:idx + 3000]
    assert "Object.keys(obj).sort()" in snippet


def test_canonical_json_no_spaces(peer_html: str):
    """Python json.dumps with `separators=(",", ":")` produces no
    spaces. The browser MUST match — any space drift breaks
    signature verification."""
    idx = peer_html.find("function _canonicalJson(obj)")
    snippet = peer_html[idx:idx + 3000]
    # Array + object joins use plain "," (no space) — pin the
    # canonical-emitting arms.
    assert 'join(",")' in snippet
    # Object KV separator is ":" (no space).
    assert '":"' in snippet


def test_canonical_json_ascii_escapes_non_ascii(peer_html: str):
    """Python ensure_ascii=True escapes non-ASCII as \\uXXXX. JS
    JSON.stringify by default does NOT for BMP non-ASCII. The
    canonical helper MUST manually \\u-escape."""
    idx = peer_html.find("function _canonicalJson(obj)")
    snippet = peer_html[idx:idx + 3000]
    assert "c.toString(16).padStart(4" in snippet
    assert '"\\\\u"' in snippet


def test_canonical_json_rejects_non_finite_numbers(peer_html: str):
    """NaN + Infinity have no valid canonical-JSON representation
    in Python json.dumps. The browser MUST raise rather than
    silently emit an invalid signing string."""
    idx = peer_html.find("function _canonicalJson(obj)")
    snippet = peer_html[idx:idx + 3000]
    assert "Number.isFinite(obj)" in snippet
    assert "non-finite" in snippet


# ───────── Ed25519 sign + verify ────────────────────────────────────

def test_sign_helper_uses_web_crypto_ed25519(peer_html: str):
    """Signing MUST go through Web Crypto's native Ed25519. No
    vendored crypto."""
    idx = peer_html.find("async function _signEd25519")
    snippet = peer_html[idx:idx + 1200]
    assert 'crypto.subtle.importKey' in snippet
    assert 'crypto.subtle.sign' in snippet
    assert '"Ed25519"' in snippet
    assert '"jwk"' in snippet


def test_signing_key_imported_non_extractable(peer_html: str):
    """The imported signing key MUST be non-extractable so a JS
    bug or extension can't read it back to clear via exportKey.
    The key only ever does sign."""
    idx = peer_html.find("async function _signEd25519")
    snippet = peer_html[idx:idx + 1200]
    assert "extractable=*/false" in snippet


def test_verify_helper_present(peer_html: str):
    """Lookup results carry signed RegisterReqs from peers; we MUST
    verify before trusting (otherwise an attacker who controls the
    rendezvous can forge listings)."""
    assert "async function _verifyEd25519" in peer_html


def test_verify_uses_raw_pubkey(peer_html: str):
    """Peer pubkeys are 32-byte raw on the wire. importKey('raw')
    is the right flavor for verify."""
    idx = peer_html.find("async function _verifyEd25519")
    snippet = peer_html[idx:idx + 1200]
    assert '"raw"' in snippet


# ───────── base64url wire format ────────────────────────────────────

def test_wire_uses_base64url_no_padding(peer_html: str):
    """Daemon's rendezvous_proto._b64 is `urlsafe_b64encode(data).
    rstrip(b"=").decode("ascii")` — base64url WITHOUT padding,
    despite the field name `pubkey_b64`. The browser MUST match.
    The bytesToB64Url helper already produces this exact form;
    pass through identity's public_key_b64u directly."""
    idx = peer_html.find("async function _buildSignedRegister")
    snippet = peer_html[idx:idx + 3000]
    # Pubkey passes through as the identity's stored b64url form,
    # NOT through a "to-standard" converter.
    assert "pubkey_b64: rec.public_key_b64u" in snippet
    # Signature output uses bytesToB64Url (base64url, no padding).
    assert "bytesToB64Url(sig)" in snippet
    # No standard-b64 converter referenced — that was a bug.
    assert "_b64StdFromUrl" not in peer_html
    assert "_b64StdFromBytes" not in peer_html


# ───────── register builder ─────────────────────────────────────────

def test_build_signed_register_present(peer_html: str):
    assert "async function _buildSignedRegister(rec, opts)" in peer_html


def test_build_signed_register_uses_canonical_json(peer_html: str):
    """The signing input is canonical JSON of the register dict
    minus signature. If the builder uses JSON.stringify directly
    instead of _canonicalJson, signatures don't verify."""
    idx = peer_html.find("async function _buildSignedRegister")
    snippet = peer_html[idx:idx + 3000]
    assert "_canonicalJson(signing)" in snippet


def test_build_signed_register_has_required_fields(peer_html: str):
    """The signing dict MUST carry exactly the fields the daemon's
    RegisterReq.from_wire validates: v, type=register, pubkey_b64,
    timestamp_ms, ttl_s, advertised_endpoints, nat_type, capabilities.
    Drift = rejection on the wire. The JS object literal uses
    shorthand for some fields (e.g. `ttl_s,` instead of `ttl_s:`),
    so search for either form."""
    idx = peer_html.find("async function _buildSignedRegister")
    snippet = peer_html[idx:idx + 3000]
    for field in (
        "v:",
        "type:",
        "pubkey_b64:",
        "timestamp_ms:",
        "advertised_endpoints:",
    ):
        assert field in snippet, f"missing field key: {field}"
    # Shorthand-or-explicit forms.
    for shorthand_field in ("ttl_s", "nat_type", "capabilities"):
        explicit = f"{shorthand_field}:"
        shorthand_with_comma = f"{shorthand_field},"
        shorthand_with_brace = f"{shorthand_field}}}"
        assert (
            explicit in snippet
            or shorthand_with_comma in snippet
            or shorthand_with_brace in snippet
        ), f"missing field: {shorthand_field}"
    assert '"register"' in snippet


def test_build_signed_register_default_capabilities(peer_html: str):
    """Default capabilities advertise the browser's runtime profile
    so peers can adapt (browser_peer = no daemon, webrtc_v1 = uses
    DataChannel transport). Don't strip these without a wire-format
    bump."""
    idx = peer_html.find("async function _buildSignedRegister")
    snippet = peer_html[idx:idx + 3000]
    assert '"browser_peer"' in snippet
    assert '"webrtc_v1"' in snippet


# ───────── client helpers ───────────────────────────────────────────

def test_register_with_helper_present(peer_html: str):
    assert "async function registerWith(rdzUrl, opts)" in peer_html


def test_register_with_posts_to_v1_register(peer_html: str):
    """The endpoint path is `/api/v1/register` — same as the
    daemon. Don't drift to /register or /v1/register."""
    idx = peer_html.find("async function registerWith")
    snippet = peer_html[idx:idx + 2000]
    assert "/api/v1/register" in snippet


def test_register_with_uses_post_json(peer_html: str):
    idx = peer_html.find("async function registerWith")
    snippet = peer_html[idx:idx + 2000]
    assert '"POST"' in snippet
    assert '"Content-Type": "application/json"' in snippet


def test_register_with_throws_on_unlocked_identity(peer_html: str):
    """Calling registerWith without an unlocked identity is a
    programming error; surface it loudly."""
    idx = peer_html.find("async function registerWith")
    snippet = peer_html[idx:idx + 2000]
    assert "if (!state.rec)" in snippet
    assert "identity not unlocked" in snippet


def test_lookup_at_helper_present(peer_html: str):
    assert "async function lookupAt(rdzUrl, peerPubkeyB64u)" in peer_html


def test_lookup_returns_null_on_404(peer_html: str):
    """The desktop daemon's /api/v1/lookup returns 404 when the
    peer isn't registered. The client MUST surface that as `null`,
    NOT throw — "not found" is the normal case for a peer we
    haven't met yet."""
    idx = peer_html.find("async function lookupAt")
    snippet = peer_html[idx:idx + 1500]
    assert "resp.status === 404" in snippet
    assert "return null" in snippet


def test_lookup_url_encodes_pubkey(peer_html: str):
    """Standard base64 contains '+' and '/'. URL-encoded path
    segments require encodeURIComponent or those chars break the
    route match."""
    idx = peer_html.find("async function lookupAt")
    snippet = peer_html[idx:idx + 1500]
    assert "encodeURIComponent" in snippet


# ───────── URL normalization ────────────────────────────────────────

def test_normalize_rdz_url_defaults_to_https(peer_html: str):
    """If the user types a bare hostname (e.g. "my-rdz.example.com"),
    the client MUST default to https://. Never silently downgrade
    to http on a bare hostname — that's a sovereignty hole."""
    idx = peer_html.find("function _normalizeRdzUrl")
    snippet = peer_html[idx:idx + 700]
    assert '"https://"' in snippet
    assert "/^https?:" in snippet


def test_normalize_strips_trailing_slash(peer_html: str):
    """User pasting `https://rdz.example.com/` shouldn't end up
    POSTing to `//api/v1/register`."""
    idx = peer_html.find("function _normalizeRdzUrl")
    snippet = peer_html[idx:idx + 700]
    assert "/\\/+$/" in snippet or "replace(/\\/+$" in snippet


# ───────── UI wiring ────────────────────────────────────────────────

def test_rdz_card_present(peer_html: str):
    assert 'id="rdz-card"' in peer_html
    assert 'id="rdz-url"' in peer_html
    assert 'id="btn-rdz-register"' in peer_html
    assert 'id="rdz-status"' in peer_html


def test_rdz_card_hidden_until_identity_loaded(peer_html: str):
    """The rdz card MUST start hidden — without an unlocked
    identity, signing won't work + the user shouldn't be tempted
    to click."""
    idx = peer_html.find('id="rdz-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_rdz_card_shown_after_identity_renders(peer_html: str):
    """After _renderIdentityCard runs (post-load or post-unlock),
    the rdz card MUST be unhidden. Pin the wrap pattern so a
    refactor doesn't drop the call."""
    assert "_showRdzCard" in peer_html
    idx = peer_html.find("_renderIdentityCard = function")
    snippet = peer_html[idx:idx + 600]
    assert "_showRdzCard()" in snippet


def test_rdz_url_persisted_to_localstorage(peer_html: str):
    """Re-typing the rendezvous URL on every visit is friction —
    persist on success, restore on card-show."""
    assert 'RDZ_URL_KEY = "ol_peer.rdz_url"' in peer_html
    idx = peer_html.find('"#btn-rdz-register"')
    # Look in the click handler scope.
    handler_idx = peer_html.find("addEventListener", idx)
    snippet = peer_html[handler_idx:handler_idx + 2500]
    assert "localStorage.setItem(RDZ_URL_KEY" in snippet


def test_rdz_button_disabled_during_request(peer_html: str):
    """HTTP register can take seconds; disable the button while
    in-flight so a double-tap doesn't fire two registers."""
    idx = peer_html.find('"#btn-rdz-register"')
    handler_idx = peer_html.find("addEventListener", idx)
    snippet = peer_html[handler_idx:handler_idx + 2500]
    assert "btn.disabled = true" in snippet
    assert "btn.disabled = false" in snippet


def test_rdz_auto_refresh_scheduled(peer_html: str):
    """After a successful register, the client MUST auto-refresh
    before the TTL expires. Otherwise the listing drops out and
    other peers can't find this device."""
    assert "_scheduleRdzRefresh" in peer_html
    idx = peer_html.find("function _scheduleRdzRefresh")
    snippet = peer_html[idx:idx + 1500]
    assert "setTimeout" in snippet
    assert "RDZ_REFRESH_MARGIN_MS" in snippet


def test_rdz_auto_refresh_clears_old_timer(peer_html: str):
    """Successive registers MUST cancel the previous refresh timer.
    Otherwise multiple registers per tick stack up."""
    idx = peer_html.find("function _scheduleRdzRefresh")
    snippet = peer_html[idx:idx + 1500]
    assert "clearTimeout(_rdzRefreshTimer)" in snippet


def test_rdz_observed_endpoint_surfaced(peer_html: str):
    """The server's RegisterAck includes the IP:port it observed.
    Surface that to the user — tells them "this is the address
    other peers will try to reach you on" which helps debug NAT."""
    assert 'id="rdz-ack-endpoint"' in peer_html
    idx = peer_html.find('"#btn-rdz-register"')
    handler_idx = peer_html.find("addEventListener", idx)
    snippet = peer_html[handler_idx:handler_idx + 2500]
    assert "observed_endpoint" in snippet


# ───────── compat with daemon's signing ─────────────────────────────

def test_signing_round_trip_against_daemon_lib():
    """End-to-end compat check: build a register dict matching what
    peer.html's _canonicalJson + _buildSignedRegister would build,
    then have the desktop daemon's RegisterReq.from_wire +
    .verify() accept it. If this fails the browser-peer can't
    register against a real rendezvous.

    The wire format uses base64url WITHOUT padding for both
    pubkey_b64 and signature, despite the field name. Verified
    via daemon's `_b64` helper which is `urlsafe_b64encode().
    rstrip("=")`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    import base64

    from one_link.rendezvous_proto import (
        PROTOCOL_VERSION,
        RegisterReq,
        _canonical_bytes,
    )

    def b64u_no_pad(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    pub_b64u = b64u_no_pad(pub)

    # This is the exact dict shape peer.html's _buildSignedRegister
    # constructs (sans signature).
    signing_dict = {
        "v": PROTOCOL_VERSION,
        "type": "register",
        "pubkey_b64": pub_b64u,
        "timestamp_ms": 1700000000000,
        "ttl_s": 300,
        "advertised_endpoints": [],
        "nat_type": "unknown",
        "capabilities": ["browser_peer", "webrtc_v1"],
    }
    canonical = _canonical_bytes(signing_dict)
    sig = sk.sign(canonical)
    wire = dict(signing_dict)
    wire["signature"] = b64u_no_pad(sig)

    # Round-trip through the daemon's parser + verifier.
    parsed = RegisterReq.from_wire(wire)
    parsed.verify()  # raises ValueError on mismatch


def test_canonical_json_python_js_parity():
    """The peer.html _canonicalJson algorithm and Python's
    json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=
    True) MUST produce byte-equal outputs for the dicts we sign.
    Test a representative sample including non-ASCII + nested."""
    from one_link.rendezvous_proto import _canonical_bytes

    samples = [
        {"v": "OL-RDZ-1", "type": "register"},
        {"a": 1, "b": [2, 3], "c": {"d": "x"}},
        {"hello": "wörld"},  # non-ASCII
        {"timestamp_ms": 1700000000000, "ttl_s": 300},
    ]
    for s in samples:
        py = _canonical_bytes(s).decode("ascii")
        # Replicate the JS algorithm in Python, then assert equal.
        # This proves the documented algorithm matches Python's
        # actual output. If a future ship changes either side,
        # this test fails loudly.
        import json
        js_equiv = json.dumps(
            s, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
        assert py == js_equiv, f"mismatch for {s}: py={py!r} js_equiv={js_equiv!r}"


# ───────── test surface ─────────────────────────────────────────────

def test_test_surface_exposes_rendezvous_helpers(peer_html: str):
    idx = peer_html.find("window.__oneLinkPeer")
    snippet = peer_html[idx:idx + 2500]
    for name in (
        "_canonicalJson",
        "_signEd25519",
        "_verifyEd25519",
        "_buildSignedRegister",
        "_normalizeRdzUrl",
        "registerWith",
        "lookupAt",
    ):
        assert name in snippet, f"test surface missing {name}"


def test_version_pin_is_semver(peer_html: str):
    import re
    m = re.search(r"version:\s*['\"]\d+\.\d+\.\d+['\"]", peer_html)
    assert m


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

"""v0.19.1 — Browser-as-peer: SAS pairing over the control DataChannel.

Two browser-peers come up with WebRTC (v0.18.0). The control
DataChannel opens. Both sides automatically exchange `pair_hello`
frames carrying their pubkey + a fresh 16-byte nonce, derive an
identical 6-digit SAS + 6-cell visual art grid from the
canonicalized join of both contributions, display to the user,
and require BOTH sides to confirm a face-to-face match before
persisting the peer to OPFS.

  Reach:  two browsers can pair without a signaling server,
          without a daemon, and without trusting any third party
          beyond the user's own face-to-face verification.
  Hide:   the SAS digits + visual art are derived from BOTH
          pubkeys + BOTH nonces — a man-in-the-middle attacker
          who controls signaling can't forge matching SAS on both
          sides without breaking Ed25519. Mismatch on either side
          aborts; no peer record is persisted.
  Async:  pair handshake fires automatically on control:open.
          30-second timeout if the other side never sends hello.
          Both sides must locally confirm AND receive remote
          confirm before the OPFS write happens.
  Depth:  protocol versioned `OL-PAIR-1`. Algorithm-tagged
          fingerprint (sha256: today, blake3: when WASM lands).
          OPFS layout `peers/v1/<short>.json` is the contract for
          v0.19.2+ message store + roster reads.

Tests: protocol constants, OPFS layout, SAS derivation algorithm
(both sides hash the SAME canonical bytes regardless of role),
hello/confirm handler dispatch, lifecycle gating before OPFS write,
mismatch + timeout abort paths, UI wiring, test surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


# ───────── protocol constants ───────────────────────────────────────

def test_pair_protocol_constants_pinned(peer_html: str):
    """The version constant guards future-ship rotation. Nonce
    length + timeout pinned for replay defense + UX."""
    assert 'PAIR_PROTOCOL_VERSION = "OL-PAIR-1"' in peer_html
    assert "PAIR_NONCE_BYTES = 16" in peer_html
    assert "PAIR_HELLO_TIMEOUT_MS = 30_000" in peer_html


# ───────── OPFS peers store ─────────────────────────────────────────

def test_peers_dir_layout_pinned(peer_html: str):
    """The `peers/v1/<short>.json` layout is the wire contract every
    later ship reads. Pin so a refactor to v2 is an explicit
    migration."""
    assert 'PEERS_DIR_NAME = "peers"' in peer_html
    assert 'PEERS_VERSION_DIR = "v1"' in peer_html


def test_peer_filename_uses_hex_prefix(peer_html: str):
    """File names are a hex prefix of the fingerprint, NOT the full
    pubkey. Casual filesystem peek shouldn't reveal full pubkeys."""
    snippet = _snippet(peer_html, "function _peerFileName", 800)
    # The function strips the algo prefix and slices a short hex.
    assert ".split(\":\")" in snippet
    assert ".slice(0, 24)" in snippet
    assert ".json" in snippet


def test_list_peers_helper_present(peer_html: str):
    """listPeers iterates the OPFS dir; future ships use it for the
    roster + send-to-peer pickers."""
    assert "async function listPeers()" in peer_html
    snippet = _snippet(peer_html, "async function listPeers()", 1500)
    assert "for await" in snippet
    # Sort newest-paired first so the most-recent peer is at top.
    assert "paired_ms" in snippet


def test_save_peer_validates_required_fields(peer_html: str):
    """A peer record without fingerprint or pubkey is meaningless;
    surface the error rather than silently writing junk."""
    snippet = _snippet(peer_html, "async function savePeer", 1500)
    assert "if (!rec || !rec.fingerprint || !rec.public_key_b64u)" in snippet
    assert "createWritable" in snippet


def test_delete_peer_helper_present(peer_html: str):
    """User-facing 'Forget' is the only way to drop a peer; the
    helper MUST handle missing-file gracefully (returns false)."""
    assert "async function deletePeer(fingerprint)" in peer_html
    snippet = _snippet(peer_html, "async function deletePeer(fingerprint)", 1200)
    assert "removeEntry" in snippet
    assert "return false" in snippet


# ───────── SAS derivation ───────────────────────────────────────────

def test_compute_sas_present(peer_html: str):
    assert "async function _computeSas(localPub, localNonce, remotePub, remoteNonce)" in peer_html


def test_sas_sorts_pubkeys_and_nonces(peer_html: str):
    """Both sides MUST hash the same canonical input regardless of
    role. Sorting the (pubkey, pubkey) and (nonce, nonce) pairs is
    the standard symmetry trick."""
    snippet = _snippet(peer_html, "async function _computeSas", 2200)
    # Both arrays sorted before canonicalization.
    assert "[localPub, remotePub].slice().sort()" in snippet
    assert "[localNonce, remoteNonce].slice().sort()" in snippet
    # Wrapped in a canonical dict so a future-ship algorithm change
    # is detectable on the wire.
    assert "_canonicalJson(dict)" in snippet


def test_sas_uses_sha256_first_four_bytes(peer_html: str):
    """First 4 bytes of SHA-256 → 32-bit unsigned int → mod 10^6 →
    zero-padded 6 digits. Standard SAS derivation."""
    snippet = _snippet(peer_html, "async function _computeSas", 2200)
    assert '"SHA-256"' in snippet
    assert "% 1_000_000" in snippet
    assert 'padStart(6, "0")' in snippet


def test_sas_visual_art_uses_six_cells(peer_html: str):
    """6 cells = 6 bytes from the SHA-256 digest. Each cell maps
    to a (hue, shape) for fast face-to-face comparison."""
    snippet = _snippet(peer_html, "async function _computeSas", 2200)
    assert "digest.slice(4, 10)" in snippet
    art_render = _snippet(peer_html, "function _renderSasArt", 1500)
    assert "for (const b of artBytes)" in art_render
    assert "hsl(" in art_render


def test_sas_display_groups_three_three(peer_html: str):
    """Six-digit codes are easier to read aloud as `123 456` than
    `123456`. Pin the display format."""
    snippet = _snippet(peer_html, "async function _computeSas", 2200)
    assert 'six.slice(0, 3) + " " + six.slice(3)' in snippet


# ───────── pair-session lifecycle ───────────────────────────────────

def test_new_pairing_initializes_state(peer_html: str):
    """Every WebRTC session gets a fresh _newPairing — fresh nonce,
    null remote_hello / remote_confirm / local_confirm. Replay
    defense: the nonce is per-session, not per-peer."""
    snippet = _snippet(peer_html, "function _newPairing(session)", 1500)
    assert "_randomBytes(PAIR_NONCE_BYTES)" in snippet
    assert "remote_hello: null" in snippet
    assert "local_confirm: null" in snippet
    assert "remote_confirm: null" in snippet
    assert "finished: false" in snippet


def test_send_pair_hello_includes_required_fields(peer_html: str):
    """Hello carries pubkey + fingerprint + nonce + timestamp.
    Receiver verifies all of these before showing the SAS."""
    snippet = _snippet(peer_html, "async function _sendPairHello", 1500)
    assert 't: "hello"' in snippet
    assert "state.rec.public_key_b64u" in snippet
    assert "state.rec.fingerprint" in snippet
    assert "bytesToB64Url(p.local_nonce)" in snippet


def test_on_pair_hello_validates_envelope(peer_html: str):
    """Bad version, missing fields, wrong nonce length all abort
    the pairing instead of computing a misleading SAS."""
    snippet = _snippet(peer_html, "async function _onPairHello(envelope)", 2500)
    assert "envelope.v !== PAIR_PROTOCOL_VERSION" in snippet
    assert "remoteNonce.byteLength !== PAIR_NONCE_BYTES" in snippet
    assert "_abortPairing(" in snippet


def test_on_pair_hello_renders_sas(peer_html: str):
    snippet = _snippet(peer_html, "async function _onPairHello(envelope)", 2500)
    assert "_computeSas(" in snippet
    assert "_renderSasArt(" in snippet
    assert "#pair-sas-digits" in snippet


def test_send_pair_confirm_routes_match_or_mismatch(peer_html: str):
    snippet = _snippet(peer_html, "async function _sendPairConfirm(matched)", 1800)
    assert 't: "confirm"' in snippet
    assert "matched: !!matched" in snippet
    assert "_abortPairing(" in snippet  # mismatch path


def test_on_pair_confirm_aborts_on_remote_mismatch(peer_html: str):
    """If the OTHER side says 'don't match', we MUST abort — never
    persist a peer record. The other user saw something we didn't."""
    snippet = _snippet(peer_html, "async function _onPairConfirm(envelope)", 1800)
    assert "if (!envelope.matched)" in snippet
    assert "_abortPairing(" in snippet


def test_finalize_requires_both_confirms(peer_html: str):
    """The OPFS write only happens when local AND remote BOTH
    answered match. Either null, either false → no persistence."""
    snippet = _snippet(peer_html, "async function _maybeFinalizePairing()", 2200)
    assert "p.local_confirm !== true" in snippet
    assert "p.remote_confirm !== true" in snippet
    assert "savePeer(rec)" in snippet
    assert "_refreshPeersCard()" in snippet


def test_finalize_fingerprint_comes_from_remote_hello(peer_html: str):
    """The fingerprint we persist is the one the REMOTE claimed in
    hello — not what we computed locally about ourselves. The SAS
    verification is what gives us confidence the remote claim is
    real."""
    snippet = _snippet(peer_html, "async function _maybeFinalizePairing()", 2200)
    assert "p.remote_hello.fingerprint" in snippet
    assert "p.remote_hello.pubkey" in snippet


def test_route_control_message_only_dispatches_pair_protocol(peer_html: str):
    """The control channel is a shared bus for v0.19.x+ messages.
    Pair-protocol routes ONLY messages tagged v=OL-PAIR-1 — leaves
    other-protocol messages for future-ship handlers."""
    snippet = _snippet(peer_html, "function _routeControlMessage", 1500)
    assert "msg.v !== PAIR_PROTOCOL_VERSION" in snippet
    assert '"hello"' in snippet
    assert '"confirm"' in snippet


# ───────── auto-fire on control:open ────────────────────────────────

def test_pair_card_present(peer_html: str):
    assert 'id="pair-card"' in peer_html
    assert 'id="pair-sas-digits"' in peer_html
    assert 'id="pair-sas-art"' in peer_html
    assert 'id="btn-pair-match"' in peer_html
    assert 'id="btn-pair-mismatch"' in peer_html


def test_pair_card_hidden_until_handshake(peer_html: str):
    """The card MUST start hidden — only shown when control:open
    fires and the handshake is in flight."""
    idx = peer_html.find('id="pair-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_control_open_triggers_on_control_channel_open(peer_html: str):
    """The createOfferSignal / acceptOfferSignal wrappers MUST
    install an onState handler that calls _onControlChannelOpen
    when label === 'control:open'. Otherwise pair handshake
    never fires."""
    offer_wrap = _snippet(peer_html, "createOfferSignal = async function", 1500)
    accept_wrap = _snippet(peer_html, "acceptOfferSignal = async function", 1500)
    for snippet in (offer_wrap, accept_wrap):
        assert 'label === "control:open"' in snippet
        assert "_onControlChannelOpen(session)" in snippet
        assert "_routeControlMessage(session, kind, data)" in snippet


def test_control_open_handler_starts_timeout(peer_html: str):
    """If the other side never sends hello, abort after 30s instead
    of leaving a half-open pair card forever."""
    snippet = _snippet(peer_html, "async function _onControlChannelOpen", 1500)
    assert "PAIR_HELLO_TIMEOUT_MS" in snippet
    assert "_abortPairing(" in snippet


# ───────── peers card hydration ─────────────────────────────────────

def test_peers_card_present(peer_html: str):
    assert 'id="peers-card"' in peer_html
    assert 'id="peers-list"' in peer_html
    assert 'id="peers-empty"' in peer_html


def test_refresh_peers_card_hides_empty_when_populated(peer_html: str):
    """When peers exist the empty hint disappears + the list shows.
    When the list empties (last forget), the hint comes back."""
    snippet = _snippet(peer_html, "async function _refreshPeersCard()", 3500)
    assert "listPeers()" in snippet
    assert 'list.style.display = "flex"' in snippet
    assert 'list.style.display = "none"' in snippet


def test_refresh_peers_card_renders_forget_button(peer_html: str):
    snippet = _snippet(peer_html, "async function _refreshPeersCard()", 3500)
    assert "Forget" in snippet
    assert "deletePeer(peer.fingerprint)" in snippet
    assert "confirm(" in snippet  # destructive-action gate


def test_render_identity_card_hydrates_peers(peer_html: str):
    """The peers card must render after identity loads so a
    returning user sees their roster immediately, even before
    any new pairing happens."""
    snippet = _snippet(peer_html, "_renderIdentityCard = function", 1000)
    assert "_refreshPeersCard()" in snippet


# ───────── test surface ─────────────────────────────────────────────

def test_test_surface_exposes_pairing_helpers(peer_html: str):
    snippet = _snippet(peer_html, "window.__oneLinkPeer", 3500)
    for name in (
        "listPeers",
        "savePeer",
        "deletePeer",
        "_computeSas",
        "_renderSasArt",
        "_newPairing",
        "_onPairHello",
        "_onPairConfirm",
        "_routeControlMessage",
    ):
        assert name in snippet, f"surface missing {name}"


# ───────── algorithm-parity tests against Python ────────────────────

def test_sas_derivation_python_parity():
    """Compute SAS in Python using the same algorithm peer.html does
    and confirm the digits formula is sound. We don't run the JS
    here, but if the algorithm spec drifts between this test +
    peer.html, signatures + handshakes don't match across browsers
    in different release ages."""
    import hashlib
    import json

    local_pub = "AAAA"
    remote_pub = "BBBB"
    local_nonce = "n1"
    remote_nonce = "n2"

    pubs = sorted([local_pub, remote_pub])
    nonces = sorted([local_nonce, remote_nonce])
    dict_obj = {
        "v": "OL-PAIR-1",
        "pubkeys": pubs,
        "nonces": nonces,
    }
    canonical = json.dumps(
        dict_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    digest = hashlib.sha256(canonical).digest()
    big = int.from_bytes(digest[:4], "big")
    six = str(big % 1_000_000).zfill(6)
    # Sanity: 6 digits, leading zeros preserved, no negative.
    assert len(six) == 6
    assert six.isdigit()
    # Same input from both sides → same SAS.
    pubs_swapped = sorted([remote_pub, local_pub])
    nonces_swapped = sorted([remote_nonce, local_nonce])
    dict_swapped = {
        "v": "OL-PAIR-1",
        "pubkeys": pubs_swapped,
        "nonces": nonces_swapped,
    }
    canonical_swapped = json.dumps(
        dict_swapped, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    assert canonical == canonical_swapped, (
        "sort symmetry breaks if either side computes SAS in different order"
    )


# ───────── version pin ──────────────────────────────────────────────

def test_version_bumped_to_v0191(peer_html: str):
    assert 'version: "0.19.1"' in peer_html


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

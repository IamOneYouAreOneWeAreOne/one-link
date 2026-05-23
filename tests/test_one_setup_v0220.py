"""One Setup first-run foundation.

These tests pin the new setup contract at the API/UI boundary. One Setup is
state-driven, skippable, and has a technical diagnostics layer for people who
want proof without forcing normal users through jargon.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _server_src() -> str:
    return (ROOT / "src" / "one_link" / "server.py").read_text(encoding="utf-8")


def _index_html() -> str:
    return (ROOT / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")


def test_setup_api_routes_exist() -> None:
    """2026-05-22 audit Batch HH: route-table introspection instead
    of source-text grep. The grep version would still pass if a
    route line were converted to a string literal in a comment or
    moved into dead code; only execution against the real router
    proves the route is dispatchable.

    Builds a UIServer + real aiohttp app, then walks the resource
    list. Faster than spinning a full daemon + serving requests,
    and still proves the routes are wired.
    """
    from types import SimpleNamespace
    from one_link.server import UIServer

    # Minimum daemon shape UIServer.app builder touches.
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    routes_by_path: dict[str, set[str]] = {}
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if not path:
            continue
        for route in resource:
            routes_by_path.setdefault(path, set()).add(route.method)

    expected = [
        ("GET",  "/api/setup"),
        ("POST", "/api/setup"),
        ("POST", "/api/setup/device-invite"),
        ("POST", "/api/setup/device-invite/claim"),
        ("POST", "/api/setup/device-invite/confirm"),
        ("POST", "/api/setup/device-invite/reject"),
        ("GET",  "/api/setup/device-invite/qr.svg"),
    ]
    for method, path in expected:
        methods = routes_by_path.get(path, set())
        assert method in methods, (
            f"missing route {method} {path}; got methods "
            f"{sorted(methods)} for that path"
        )


def test_setup_snapshot_is_state_derived_and_human_first() -> None:
    src = _server_src()
    idx = src.find("def _one_setup_snapshot(")
    assert idx > 0
    snippet = src[idx:idx + 14000]
    assert "state.list_self_mesh_roots()" in snippet
    assert "state.list_self_mesh_devices()" in snippet
    assert "state.list_self_mesh_presence()" in snippet
    assert '"mode": "human"' in snippet
    assert '"technical": {' in snippet
    assert '"diagnostics": diagnostics' in snippet
    assert '"privacy_proof": privacy_proof' in snippet
    assert '"audit_events": proof_events' in snippet
    assert '"receipt_redacted": True' in snippet
    assert '"next_action"' in snippet
    for item in (
        "One identity",
        "This device",
        "Add phone or laptop",
        "First message",
        "First file",
        "Privacy proof",
        "Device safety",
        "Recovery",
    ):
        assert item in snippet


def test_setup_post_actions_cover_skip_complete_and_real_milestones() -> None:
    src = _server_src()
    idx = src.find("async def api_update_setup(")
    assert idx > 0
    snippet = src[idx:idx + 5000]
    for action in (
        '"skip"',
        '"complete"',
        '"privacy_proof_viewed"',
        '"safety_reviewed"',
        '"first_message_sent"',
        '"first_file_sent"',
        '"recovery_configured"',
        '"reset"',
    ):
        assert action in snippet
    assert 'state.set_setting("onboarding_completed", "true")' in snippet
    assert "unsupported setup action" in snippet


def test_setup_device_invite_claim_requires_host_confirmation() -> None:
    src = _server_src()
    idx = src.find("async def api_setup_device_invite_claim(")
    assert idx > 0
    snippet = src[idx:idx + 5000]
    assert "device_pub_b64" in snippet
    assert "pending_claim" in snippet
    assert "compute_sas" in snippet
    assert "format_sas" in snippet
    assert "setup_device_invite_pending" in snippet
    assert '"pending": True' in snippet
    assert "invite expired or not found" in snippet


def test_device_invite_claim_route_is_public_not_ui_token_gated() -> None:
    """2026-05-23: /api/setup/device-invite/claim is the bootstrap
    endpoint for a NEW device that has no credentials yet. The
    request body carries the ``setup_device_invite`` token, which
    the handler validates against ``_setup_device_invites``. The
    invite IS the auth. Wrapping the route in ``_guarded`` would
    require the desktop UI's bearer/cookie token, which a phone
    on a different Origin cannot have — pairing dead-ends at
    HTTP 401 "unauthorized" with the device sitting on the peer
    page showing "Couldn't add this device: unauthorized."

    /confirm and /reject MUST stay guarded — they're called by
    the desktop after the operator verbally compares the SAS.
    """
    src = _server_src()
    # /claim line: no _guarded wrapper.
    claim_line_idx = src.find(
        'r.add_post("/api/setup/device-invite/claim",'
    )
    assert claim_line_idx > 0
    # The route handler reference on that line must NOT be wrapped
    # in self._guarded(...) — it must be a bare method reference.
    line_end = src.find("\n", claim_line_idx)
    claim_line = src[claim_line_idx:line_end]
    assert "self._guarded(" not in claim_line, (
        f"/claim route is gated by _guarded — phone bootstrap "
        f"will 401. Line: {claim_line!r}"
    )

    # /confirm + /reject MUST stay guarded — these are
    # desktop-initiated after the SAS match.
    for guarded in ("/api/setup/device-invite/confirm", "/api/setup/device-invite/reject"):
        idx = src.find(f'r.add_post("{guarded}",')
        assert idx > 0
        line = src[idx:src.find("\n", idx)]
        assert "self._guarded(" in line, (
            f"{guarded} must stay _guarded (desktop-initiated). "
            f"Line: {line!r}"
        )

    # Handler must have its own IP-based rate limit to replace the
    # one that lived in _guarded.
    handler_idx = src.find("async def api_setup_device_invite_claim(")
    snippet = src[handler_idx:handler_idx + 2000]
    assert '"device_invite_claim"' in snippet
    assert "_rate_limited(" in snippet
    assert "too many claim attempts" in snippet


def test_setup_device_invite_confirm_caches_webrtc_handoff() -> None:
    """2026-05-23: when /confirm succeeds, the invite record must
    cache the WebRTC handoff bundle (pair_token + daemon_fingerprint
    + ws_signaling_url + daemon_pubkey_b64u) under device_row so
    the phone's /status poll can pick them up and run
    _runAutoPairFlow to actually open a live control channel.
    Without these the phone ends with a device cert but no live
    link and dead-ends at the 'trusted' card.
    """
    src = _server_src()
    confirm_idx = src.find("async def api_setup_device_invite_confirm(")
    assert confirm_idx > 0
    confirm = src[confirm_idx:confirm_idx + 6000]
    # The helper must be called and its result spread into
    # device_row so /status can return it to the phone.
    assert "_setup_device_invite_pair_handoff" in confirm
    assert "**pair_handoff" in confirm


def test_setup_device_invite_relogin_endpoint_pinned() -> None:
    """2026-05-23: phone auto-reconnect after daemon restart.

    Phone has long-lived device cert in localStorage. After a tab
    reload / daemon restart, the WebRTC session is dead and the
    original pair_token is gone. Without /relogin the only way
    back is a fresh QR-scan pair — clunky enough that the user
    experiences daemon restarts as 'the phone broke'.

    Endpoint MUST:
      * be public (cert + sig-on-nonce is the auth, not a UI bearer
        token);
      * accept POST with {cert_b64, nonce_b64, sig_b64};
      * validate the cert chain against this daemon's root via
        verify_device_cert;
      * verify the sig over the nonce with the cert's device_pub
        (proves the phone holds the private key);
      * confirm the device is in the trusted roster (not revoked);
      * return the same handoff shape /status confirmed returns so
        the phone's existing autopair bootstrap accepts it unchanged;
      * be IP-rate-limited.
    """
    src = _server_src()
    # Route registration: must be public (no _guarded wrapper).
    line_idx = src.find(
        'r.add_post("/api/setup/device-invite/relogin",'
    )
    assert line_idx > 0
    line_end = src.find("\n", line_idx)
    route_line = src[line_idx:line_end]
    assert "self._guarded(" not in route_line, (
        "relogin must be PUBLIC — auth is the cert, not a UI token"
    )

    # Handler exists + implements the contract.
    handler_idx = src.find("async def api_setup_device_invite_relogin(")
    assert handler_idx > 0
    handler = src[handler_idx:handler_idx + 8000]
    # Validates inputs.
    assert "cert_b64" in handler
    assert "nonce_b64" in handler
    assert "sig_b64" in handler
    # Rate-limits (per IP, same bucket pattern as /claim + /status).
    assert "_rate_limited(" in handler
    assert "device_invite_relogin" in handler
    # Calls verify_device_cert against this daemon's root.
    assert "verify_device_cert" in handler
    assert "list_self_mesh_roots" in handler
    # Verifies sig on the nonce.
    assert "Ed25519PublicKey" in handler
    assert "InvalidSignature" in handler
    # Checks device is in the trusted roster + not revoked.
    assert "list_self_mesh_devices" in handler
    assert "revoked" in handler
    # Returns the same handoff bundle /status confirmed returns.
    assert "_setup_device_invite_pair_handoff()" in handler


def test_setup_device_invite_ttl_is_30_minutes() -> None:
    """2026-05-23 user feedback: 5 min invite expired during the iOS
    profile install walk. 30 min keeps the window security-bounded
    while letting the realistic install flow finish (download
    profile + Settings install + passcode + Trust Settings toggle
    is 3-10 min, longer if the user is interrupted).
    """
    src = _server_src()
    idx = src.find("async def api_setup_device_invite(")
    assert idx > 0
    snippet = src[idx:idx + 5000]
    assert "expires_ms = now + 30 * 60 * 1000" in snippet, (
        "invite TTL must be 30 min — 5 min expired before users "
        "could finish the iOS profile install walk"
    )


def test_peer_shell_emits_etag_for_cache_busting() -> None:
    """2026-05-23 bugfix: stale peer.html cached on iOS Safari
    survived no-store and showed the OLD UI (with the wrong-flow
    'Claim this device' button) after every fix. ETag based on
    SHA-256 of the body bytes + no-cache/must-revalidate forces a
    conditional GET on every load — 304 for unchanged, 200 +
    fresh body the moment we ship a code change. Bullet-proof
    cache busting without forcing the user to Clear-Website-Data.
    """
    src = _server_src()
    idx = src.find("async def _peer_shell(")
    assert idx > 0
    snippet = src[idx:idx + 3000]
    assert "ETag" in snippet
    assert "hashlib.sha256" in snippet
    assert "If-None-Match" in snippet
    assert "no-cache" in snippet
    assert "must-revalidate" in snippet
    # And a 304 path must exist so unchanged content is cheap.
    assert "status=304" in snippet


def test_phone_facing_daemon_fingerprint_uses_wire_format() -> None:
    """2026-05-23: every place the daemon ships its identity
    fingerprint to peer.html MUST use ``me.wire_fingerprint``
    (sha256-tagged) — not ``me.fingerprint`` (BLAKE3 hex).
    Browser-side _verifySignedDaemonAnswer re-derives sha256 from
    the daemon's pubkey and compares to the envelope's
    daemon_fingerprint; the BLAKE3 form fails this check
    universally because Web Crypto has no BLAKE3.

    Three call sites:
      1. api_mint_pairing      (autopair QR flow)
      2. peer_rtc signed-answer envelope
      3. _setup_device_invite_pair_handoff (cert-pair handoff)

    Any of them slipping back to me.fingerprint silently dead-ends
    every phone pair attempt with "daemon_fingerprint does not
    match sha256(daemon_pubkey)".
    """
    src = _server_src()

    # Call site 1: api_mint_pairing.
    idx = src.find("async def api_mint_pairing(")
    assert idx > 0
    snippet = src[idx:idx + 5000]
    assert "wire_fingerprint" in snippet, (
        "api_mint_pairing must use me.wire_fingerprint"
    )
    # Defensive: the bare me.fingerprint should NOT appear in
    # this snippet anywhere outside of comments.
    assert "self.daemon.me.fingerprint" not in snippet, (
        "api_mint_pairing leaked me.fingerprint — use wire_fingerprint"
    )

    # Call site 2: peer_rtc answer envelope. Find the line where
    # daemon_fingerprint is set in the answer dict.
    answer_idx = src.find('"daemon_fingerprint": self.daemon.me.wire_fingerprint')
    assert answer_idx > 0, (
        "answer envelope still uses BLAKE3 daemon.me.fingerprint — "
        "phone _verifySignedDaemonAnswer will fail"
    )

    # Call site 3: _setup_device_invite_pair_handoff helper.
    idx = src.find("def _setup_device_invite_pair_handoff(")
    assert idx > 0
    snippet = src[idx:idx + 2500]
    assert "wire_fingerprint" in snippet, (
        "pair handoff helper must use me.wire_fingerprint"
    )


def test_setup_device_invite_pair_handoff_shape() -> None:
    """The handoff helper builds the same field set the autopair
    QR mints. Phone-side peer.html relies on exactly:
      pair_token, daemon_fingerprint, ws_signaling_url,
      daemon_pubkey_b64u
    Any rename here breaks the phone's WebRTC bootstrap silently.
    """
    src = _server_src()
    helper_idx = src.find("def _setup_device_invite_pair_handoff(")
    assert helper_idx > 0
    helper = src[helper_idx:helper_idx + 2500]
    for field in (
        '"pair_token"',
        '"daemon_fingerprint"',
        '"daemon_pubkey_b64u"',
        '"ws_signaling_url"',
    ):
        assert field in helper, f"handoff missing {field}"
    # Must reuse mint_pairing_token (single-use signaling auth)
    # rather than rolling its own token format.
    assert "mint_pairing_token" in helper


def test_setup_device_invite_confirm_mints_cert_and_reject_blocks() -> None:
    src = _server_src()
    confirm_idx = src.find("async def api_setup_device_invite_confirm(")
    reject_idx = src.find("async def api_setup_device_invite_reject(")
    assert confirm_idx > 0
    assert reject_idx > 0
    confirm = src[confirm_idx:confirm_idx + 5000]
    reject = src[reject_idx:reject_idx + 2500]
    assert "pending_claim" in confirm
    assert "mint_device_cert" in confirm
    assert "upsert_self_mesh_device" in confirm
    assert '"source": "one_setup_invite_confirmed"' in confirm
    assert "setup_device_invite_confirmed" in confirm
    assert "setup_device_invite_rejected" in reject
    assert "codes did not match" in reject


def test_setup_device_invite_qr_opens_peer_shell() -> None:
    src = _server_src()
    idx = src.find("async def api_setup_device_invite_qr(")
    snippet = src[idx:idx + 1600]
    assert "_setup_invite_peer_url(request, token)" in snippet
    assert "/peer?setup_device_invite=" in src
    invite_idx = src.find("async def api_setup_device_invite(")
    invite_snippet = src[invite_idx:invite_idx + 3500]
    assert '"peer_url": self._setup_invite_peer_url(request, token)' in invite_snippet


def test_me_surfaces_one_setup_compatibility_flags() -> None:
    src = _server_src()
    idx = src.find("async def api_me(")
    snippet = src[idx:idx + 3200]
    assert '"one_setup_completed": one_setup_completed' in snippet
    assert '"one_setup_skipped_at_ms": one_setup_skipped_at_ms' in snippet
    assert 'state.get_setting("one_setup_completed")' in snippet
    assert 'state.get_setting("one_setup_skipped_at_ms")' in snippet


def test_one_setup_ui_contract_markers_present_after_build() -> None:
    html = _index_html()
    for marker in (
        "You are One",
        "Set up One Link",
        "Skip for now",
        "Name this device",
        "Create your One identity",
        "Add your phone or laptop",
        "Send something to yourself",
        "Technical setup details",
        'id="one-setup-panel"',
        'id="one-setup-resume"',
        'id="one-setup-panel-technical"',
        'data-settings-pane="setup"',
        'id="settings-one-setup-list"',
        'id="settings-one-setup-proof-list"',
        'id="settings-one-setup-technical-list"',
        'id="settings-one-setup-recovery"',
        'id="one-setup-safety-panel"',
        'id="one-setup-review-safety"',
        'id="one-setup-invite-qr"',
        'id="one-setup-invite-token"',
        'id="one-setup-copy-invite"',
        'id="one-setup-pending-device"',
        'id="one-setup-trust-code"',
        'id="one-setup-codes-yes"',
        'id="one-setup-codes-no"',
        "Technical verification",
        "function refreshOneSetup()",
        "function renderOneSetup()",
        "async function skipOneSetup()",
        "async function createOneSetupIdentity()",
        "async function oneSetupSendTest()",
        "async function oneSetupSendFile()",
        "async function oneSetupReviewSafety()",
        "async function oneSetupAddDevice()",
        "function renderOneSetupInviteCountdown()",
        "async function oneSetupMarkRecoveryConfigured()",
        "async function openOneSetupFromState()",
        "async function oneSetupConfirmPendingDevice()",
        "async function oneSetupRejectPendingDevice()",
        'setupDeviceInvite(body) { return this.post("/api/setup/device-invite", body); }',
        'claimSetupDeviceInvite(body) { return this.post("/api/setup/device-invite/claim", body); }',
        'confirmSetupDeviceInvite(body) { return this.post("/api/setup/device-invite/confirm", body); }',
        'rejectSetupDeviceInvite(body) { return this.post("/api/setup/device-invite/reject", body); }',
        "Invite ready and copied.",
        "Invite expired. Create a fresh QR before adding another device.",
        'api.setupAction("recovery_configured")',
        "invite.peer_url",
        "hello-from-one-link.txt",
        "This moved through your private One Link fabric.",
        'api.setupAction("first_file_sent")',
        'api.setupAction("safety_reviewed")',
        'api.setupAction("complete")',
        'api.setupAction("skip")',
    ):
        assert marker in html


def test_one_setup_walkthrough_can_reach_all_six_steps() -> None:
    html = _index_html()
    assert "const N = 6;" in html
    assert "if (step >= 1 && step <= 6) showOnboardingStep(step);" in html
    for marker in (
        'data-onboarding-go="5"',
        'data-onboarding-go="6"',
        'id="one-setup-send-test"',
        'id="one-setup-send-file"',
        'id="onboarding-finish"',
    ):
        assert marker in html

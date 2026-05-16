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
    src = _server_src()
    assert 'r.add_get("/api/setup", self._guarded(self.api_setup_status))' in src
    assert 'r.add_post("/api/setup", self._guarded(self.api_update_setup))' in src
    assert 'r.add_post("/api/setup/device-invite", self._guarded(self.api_setup_device_invite))' in src
    assert 'r.add_post("/api/setup/device-invite/claim", self._guarded(self.api_setup_device_invite_claim))' in src
    assert 'r.add_post("/api/setup/device-invite/confirm", self._guarded(self.api_setup_device_invite_confirm))' in src
    assert 'r.add_post("/api/setup/device-invite/reject", self._guarded(self.api_setup_device_invite_reject))' in src
    assert 'r.add_get("/api/setup/device-invite/qr.svg", self._guarded(self.api_setup_device_invite_qr))' in src


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

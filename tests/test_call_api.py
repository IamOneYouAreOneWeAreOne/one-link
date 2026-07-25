"""Tests for the CallAPI adapter — JSON entry point for the UI."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.call_api import (
    ApiRequest,
    ApiResponse,
    CallAPI,
    CallAction,
)
from one_link.call_manager import CallManagerRegistry, ManagerEvent, ManagerEventKind
from one_link.call_signaling import CALL_END, CALL_INVITE
from one_link.identity import Identity
from one_link.recording_consent import RECORDING_REQUEST


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _identity(name: str) -> Identity:
    seed = blake3.blake3(name.encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv, public=priv.public_key(), public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=name,
    )


@pytest.fixture
def alice() -> Identity:
    return _identity("alice-api")


@pytest.fixture
def mom() -> Identity:
    return _identity("mom-api")


@pytest.fixture
def alice_api(alice: Identity) -> CallAPI:
    return CallAPI(
        registry=CallManagerRegistry(),
        local_master_vk_hex=alice.fingerprint,
    )


# ---------------------------------------------------------------------------
# Initiate
# ---------------------------------------------------------------------------

def test_initiate_opens_call_and_emits_invite(
    alice_api: CallAPI, mom: Identity,
) -> None:
    resp = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    assert resp.ok
    assert resp.call_id is not None
    assert resp.call_id.startswith("call-")
    assert resp.phase == "inviting"
    # An outbound CALL_INVITE message is queued.
    invites = [m for m in resp.outbound if m.type == CALL_INVITE]
    assert len(invites) == 1
    assert invites[0].peer_master_vk_hex == mom.fingerprint


def test_initiate_without_peer_returns_user_message(
    alice_api: CallAPI,
) -> None:
    resp = alice_api.handle(ApiRequest(action=CallAction.INITIATE))
    assert not resp.ok
    # Plain-language message — doctrine §3.2.d (no error codes)
    assert "someone" in resp.user_message.lower()
    for forbidden in ("0x", "error code", "captcha"):
        assert forbidden not in resp.user_message.lower()


def test_initiate_is_idempotent_with_active_call(
    alice_api: CallAPI, mom: Identity,
) -> None:
    """Tapping Call Mom twice doesn't open a second call to her;
    the existing call_id is returned."""
    r1 = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    r2 = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    assert r1.ok and r2.ok
    assert r1.call_id == r2.call_id


def test_initiate_carries_negotiated_capabilities(
    alice_api: CallAPI, mom: Identity,
) -> None:
    caps = frozenset({"webrtc_av_v1", "frame_provenance_v1"})
    resp = alice_api.initiate(
        peer_master_vk_hex=mom.fingerprint,
        negotiated_capabilities=caps,
    )
    assert resp.ok
    mgr = alice_api._registry.get(resp.call_id)  # type: ignore[arg-type]
    assert mgr is not None
    session = mgr.session_snapshot()
    assert "webrtc_av_v1" in session.negotiated_capabilities


# ---------------------------------------------------------------------------
# Accept / decline / hangup
# ---------------------------------------------------------------------------

def test_accept_unknown_call_returns_plain_refusal(
    alice_api: CallAPI,
) -> None:
    resp = alice_api.handle(ApiRequest(
        action=CallAction.ACCEPT, call_id="nonexistent",
    ))
    assert not resp.ok
    # Any refusal at all is fine — the assertion below is the
    # load-bearing one: doctrine §3.2.d (no error codes leak)
    assert resp.user_message != ""
    for forbidden in ("0x", "error", "code", "captcha", "failed"):
        assert forbidden not in resp.user_message.lower()


def test_hangup_active_call_emits_end_and_completes(
    alice_api: CallAPI, mom: Identity,
) -> None:
    r1 = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    call_id = r1.call_id
    assert call_id

    # Pretend Mom accepted (drive the lifecycle directly)
    mgr = alice_api._registry.get(call_id)
    assert mgr is not None
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 1_000))
    assert mgr.phase.name == "ACTIVE"

    # Now Alice hangs up via the API
    resp = alice_api.handle(ApiRequest(
        action=CallAction.HANGUP, call_id=call_id,
    ))
    assert resp.ok
    assert resp.phase == "ended"
    assert resp.call_complete is True
    # One outbound CALL_END
    ends = [m for m in resp.outbound if m.type == CALL_END]
    assert len(ends) == 1


def test_convert_to_async_action_opens_real_capsule_capture(
    alice_api: CallAPI, mom: Identity,
) -> None:
    initiated = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    assert initiated.call_id is not None
    manager = alice_api._registry.get(initiated.call_id)
    assert manager is not None
    manager.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))

    response = alice_api.handle_json({
        "action": "convert_to_async",
        "call_id": initiated.call_id,
    })

    assert response.ok is True
    assert response.phase == "async_capture"
    assert manager.state.capsule_builder is not None
    assert manager.state.capsule_builder.is_empty()


# ---------------------------------------------------------------------------
# Recording flow
# ---------------------------------------------------------------------------

def test_request_recording_emits_request_message(
    alice_api: CallAPI, mom: Identity,
) -> None:
    r1 = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    call_id = r1.call_id
    mgr = alice_api._registry.get(call_id)
    assert mgr is not None
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 1_000))

    resp = alice_api.handle(ApiRequest(
        action=CallAction.REQUEST_RECORDING, call_id=call_id,
    ))
    assert resp.ok
    requests = [m for m in resp.outbound if m.type == RECORDING_REQUEST]
    assert len(requests) == 1


def test_approve_recording_on_remote_request(
    alice_api: CallAPI, mom: Identity,
) -> None:
    """Mom initiated recording; Alice approves via API."""
    r1 = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    call_id = r1.call_id
    mgr = alice_api._registry.get(call_id)
    assert mgr is not None
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 1_000))
    mgr.handle(ManagerEvent(
        ManagerEventKind.WIRE_RECORDING_REQUEST, 2_000,
    ))
    resp = alice_api.handle(ApiRequest(
        action=CallAction.APPROVE_RECORDING, call_id=call_id,
    ))
    assert resp.ok
    assert resp.consent_phase == "recording"


# ---------------------------------------------------------------------------
# JSON-shaped requests (HTTP layer style)
# ---------------------------------------------------------------------------

def test_handle_json_initiate(alice_api: CallAPI, mom: Identity) -> None:
    resp = alice_api.handle_json({
        "action": "initiate",
        "peer_master_vk_hex": mom.fingerprint,
        "negotiated_capabilities": ["webrtc_av_v1"],
    })
    assert resp.ok
    assert resp.call_id is not None


@pytest.mark.parametrize("call_kind", ["voice", "video"])
def test_initiate_binds_and_propagates_call_kind(
    alice_api: CallAPI,
    mom: Identity,
    call_kind: str,
) -> None:
    resp = alice_api.handle_json({
        "action": "initiate",
        "peer_master_vk_hex": mom.fingerprint,
        "kind": call_kind,
    })
    assert resp.ok
    assert resp.call_kind == call_kind
    assert resp.call_id is not None
    mgr = alice_api._registry.get(resp.call_id)
    assert mgr is not None
    assert mgr.state.call_kind == call_kind
    invites = [item for item in resp.outbound if item.type == CALL_INVITE]
    assert len(invites) == 1
    assert invites[0].payload["call_kind"] == call_kind


def test_initiate_defaults_legacy_request_to_voice(
    alice_api: CallAPI,
    mom: Identity,
) -> None:
    resp = alice_api.handle_json({
        "action": "initiate",
        "peer_master_vk_hex": mom.fingerprint,
    })
    assert resp.ok
    assert resp.call_kind == "voice"
    assert resp.outbound[0].payload["call_kind"] == "voice"


@pytest.mark.parametrize("call_kind", ["screen", "", 7, ["video"]])
def test_initiate_rejects_invalid_call_kind_without_allocating(
    alice_api: CallAPI,
    mom: Identity,
    call_kind,
) -> None:
    resp = alice_api.handle_json({
        "action": "initiate",
        "peer_master_vk_hex": mom.fingerprint,
        "kind": call_kind,
    })
    assert not resp.ok
    assert len(alice_api._registry) == 0


def test_handle_json_accepts_uppercase_action(
    alice_api: CallAPI, mom: Identity,
) -> None:
    """Case-insensitive action names tolerate browsers that send
    "Initiate" or "INITIATE"."""
    resp = alice_api.handle_json({
        "action": "INITIATE",
        "peer_master_vk_hex": mom.fingerprint,
    })
    assert resp.ok


def test_handle_json_rejects_unknown_action(alice_api: CallAPI) -> None:
    resp = alice_api.handle_json({"action": "self_destruct"})
    assert not resp.ok
    assert "not available" in resp.user_message.lower()


def test_handle_json_rejects_non_dict() -> None:
    api = CallAPI(
        registry=CallManagerRegistry(),
        local_master_vk_hex="abc",
    )
    resp = api.handle_json("not a dict")  # type: ignore[arg-type]
    assert not resp.ok


def test_handle_json_missing_action(alice_api: CallAPI) -> None:
    resp = alice_api.handle_json({"call_id": "x"})
    assert not resp.ok


# ---------------------------------------------------------------------------
# Status / list_active
# ---------------------------------------------------------------------------

def test_status_unknown_call(alice_api: CallAPI) -> None:
    resp = alice_api.status("ghost")
    assert not resp.ok


def test_status_active_call_returns_phase(
    alice_api: CallAPI, mom: Identity,
) -> None:
    r1 = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    s = alice_api.status(r1.call_id)
    assert s.ok
    assert s.phase == "inviting"


def test_list_active_returns_all_open_calls(
    alice_api: CallAPI, mom: Identity,
) -> None:
    other = _identity("other-peer")
    r1 = alice_api.initiate(peer_master_vk_hex=mom.fingerprint)
    r2 = alice_api.initiate(peer_master_vk_hex=other.fingerprint)
    listed = alice_api.list_active()
    call_ids = sorted(r.call_id for r in listed if r.call_id)
    assert call_ids == sorted([r1.call_id, r2.call_id])


# ---------------------------------------------------------------------------
# Doctrine: no error-code leakage in user_message
# ---------------------------------------------------------------------------

_FORBIDDEN_USER_TOKENS = (
    "0x", "error code", "captcha", "failed", "reconnecting",
    "please try again",
)


def test_all_refusal_messages_doctrine_compliant() -> None:
    """Synthesise every refusal path and verify the user_message is
    plain language. The internal server_log can carry codes; the
    user-facing message must not."""
    api = CallAPI(
        registry=CallManagerRegistry(),
        local_master_vk_hex="abc",
    )
    refusals: list[ApiResponse] = []
    refusals.append(api.handle(ApiRequest(action=CallAction.INITIATE)))  # no peer
    refusals.append(api.handle(ApiRequest(
        action=CallAction.HANGUP, call_id="nope",
    )))
    refusals.append(api.handle_json({"action": "unknown"}))
    refusals.append(api.handle_json({"call_id": "x"}))    # missing action
    refusals.append(api.handle_json("plain string"))      # not a dict
    refusals.append(api.status("ghost"))

    for resp in refusals:
        assert not resp.ok
        msg_lower = resp.user_message.lower()
        for tok in _FORBIDDEN_USER_TOKENS:
            assert tok not in msg_lower, (
                f"refusal leaks {tok!r}: {resp.user_message!r}"
            )


# ---------------------------------------------------------------------------
# Defensive: crashing inside handle() flows as a calm refusal
# ---------------------------------------------------------------------------

def test_handle_swallows_exceptions(alice_api: CallAPI, monkeypatch) -> None:
    """If the internal dispatch raises, the API returns a calm
    refusal — never lets the exception escape."""
    def _boom(req: ApiRequest) -> ApiResponse:
        raise RuntimeError("synthetic blow-up")
    monkeypatch.setattr(alice_api, "_dispatch", _boom)
    resp = alice_api.handle(ApiRequest(action=CallAction.INITIATE))
    assert not resp.ok
    assert "moment" in resp.user_message.lower() or "didn't work" in resp.user_message.lower()

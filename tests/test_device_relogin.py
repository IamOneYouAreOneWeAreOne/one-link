from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.device_relogin import (
    DeviceReloginChallengeCapacityError,
    DeviceReloginChallengeError,
    DeviceReloginChallengeStore,
    RELOGIN_CHALLENGE_ID_BYTES,
    RELOGIN_CHALLENGE_NONCE_BYTES,
    RELOGIN_PROOF_DOMAIN,
    decode_b64u_strict,
    encode_b64u,
)
from one_link.identity import Identity, fingerprint_of
from one_link.pairing import compute_setup_sas_words, format_sas_words
from one_link.peer_rtc import BrowserPeerManager
from one_link.self_mesh_enrollment import MeshRoot, mint_device_cert
from one_link.server import UIServer
from one_link.state import State


def _identity(hostname: str = "relogin-daemon") -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname=hostname,
    )


class _JsonRequest:
    def __init__(
        self,
        body: Any,
        *,
        remote: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 iPhone Safari/605.1",
    ) -> None:
        self._body = body
        self.remote = remote
        self.transport = None
        self.headers = {"User-Agent": user_agent}

    async def json(self) -> Any:
        return self._body


class _MalformedJsonRequest(_JsonRequest):
    async def json(self) -> Any:
        raise ValueError("synthetic malformed JSON")


def _response_json(response: Any) -> dict[str, Any]:
    return json.loads(response.body.decode("utf-8"))


@pytest.fixture
def enrolled_server(tmp_path: Path) -> tuple[
    UIServer,
    State,
    MeshRoot,
    Ed25519PrivateKey,
    bytes,
]:
    state = State(db_path=tmp_path / "relogin-state.db")
    root = MeshRoot.create()
    state.upsert_self_mesh_root(
        root_pub=root.root_pub,
        root_seed=root.root_seed,
        label="My devices",
    )
    device_private = Ed25519PrivateKey.generate()
    device_pub = device_private.public_key().public_bytes_raw()
    cert = mint_device_cert(
        root_seed=root.root_seed,
        root_pub=root.root_pub,
        device_pub=device_pub,
        device_kind="phone-ios",
    )
    state.upsert_self_mesh_device(
        root_pub=root.root_pub,
        device_pub=device_pub,
        cert=cert,
        device_kind="phone-ios",
        label="Josh's phone",
        local=False,
        trusted=True,
    )
    daemon = SimpleNamespace(state=state, me=_identity())
    peer_rtc = BrowserPeerManager(daemon)
    server = UIServer.__new__(UIServer)
    server.daemon = daemon
    server.peer_rtc = peer_rtc
    server.bind_host = "127.0.0.1"
    server.https_port = 0
    server.port = 18443
    server._rate_buckets = {}
    server._setup_device_invites = {}
    server._setup_device_invites_lock = asyncio.Lock()
    server._device_relogin_challenges = DeviceReloginChallengeStore()
    try:
        yield server, state, root, device_private, cert
    finally:
        state.close()


def test_strict_base64url_rejects_aliases_and_size_before_decode() -> None:
    encoded = encode_b64u(b"x" * 32)
    assert decode_b64u_strict(
        encoded,
        field="sample",
        exact_bytes=32,
        max_bytes=32,
    ) == b"x" * 32
    for invalid in (encoded + "=", encoded + "!", "", "A", "A" * 44):
        with pytest.raises(DeviceReloginChallengeError):
            decode_b64u_strict(
                invalid,
                field="sample",
                exact_bytes=32,
                max_bytes=32,
            )


def test_challenge_is_unique_bound_single_use_and_domain_separated() -> None:
    store = DeviceReloginChallengeStore()
    device = secrets.token_bytes(32)
    root = secrets.token_bytes(32)
    daemon = secrets.token_bytes(32)
    first = store.issue(device_pub=device, root_pub=root, daemon_pub=daemon)
    second = store.issue(device_pub=device, root_pub=root, daemon_pub=daemon)

    assert first.challenge_id != second.challenge_id
    assert len(first.challenge_id_bytes) == RELOGIN_CHALLENGE_ID_BYTES
    assert len(first.nonce) == RELOGIN_CHALLENGE_NONCE_BYTES
    assert first.proof.startswith(RELOGIN_PROOF_DOMAIN)
    assert device in first.proof
    assert root in first.proof
    assert daemon in first.proof
    assert store.consume(
        first.challenge_id,
        device_pub=device,
        root_pub=root,
        daemon_pub=daemon,
    ) == first
    with pytest.raises(DeviceReloginChallengeError, match="already used"):
        store.consume(
            first.challenge_id,
            device_pub=device,
            root_pub=root,
            daemon_pub=daemon,
        )


@pytest.mark.parametrize("mismatch", ["device", "root", "daemon"])
def test_binding_mismatch_fails_and_consumes_known_challenge(mismatch: str) -> None:
    store = DeviceReloginChallengeStore()
    keys = {
        "device": secrets.token_bytes(32),
        "root": secrets.token_bytes(32),
        "daemon": secrets.token_bytes(32),
    }
    record = store.issue(
        device_pub=keys["device"],
        root_pub=keys["root"],
        daemon_pub=keys["daemon"],
    )
    supplied = dict(keys)
    supplied[mismatch] = secrets.token_bytes(32)
    with pytest.raises(DeviceReloginChallengeError, match="does not match"):
        store.consume(
            record.challenge_id,
            device_pub=supplied["device"],
            root_pub=supplied["root"],
            daemon_pub=supplied["daemon"],
        )
    assert store.pending_count() == 0
    with pytest.raises(DeviceReloginChallengeError, match="already used"):
        store.consume(
            record.challenge_id,
            device_pub=keys["device"],
            root_pub=keys["root"],
            daemon_pub=keys["daemon"],
        )


def test_expiry_uses_monotonic_clock_despite_wall_clock_rollback() -> None:
    clock = {"mono": 1_000, "unix": 50_000}
    store = DeviceReloginChallengeStore(
        ttl_ms=500,
        monotonic_ms=lambda: clock["mono"],
        unix_ms=lambda: clock["unix"],
    )
    device, root, daemon = (secrets.token_bytes(32) for _ in range(3))
    record = store.issue(device_pub=device, root_pub=root, daemon_pub=daemon)
    clock["mono"] += 501
    clock["unix"] -= 10_000
    with pytest.raises(DeviceReloginChallengeError, match="expired"):
        store.consume(
            record.challenge_id,
            device_pub=device,
            root_pub=root,
            daemon_pub=daemon,
        )


def test_challenge_capacity_is_global_per_device_and_recovers_after_expiry() -> None:
    clock = {"mono": 10, "unix": 20}
    store = DeviceReloginChallengeStore(
        ttl_ms=100,
        max_entries=3,
        max_per_device=2,
        monotonic_ms=lambda: clock["mono"],
        unix_ms=lambda: clock["unix"],
    )
    root = secrets.token_bytes(32)
    daemon = secrets.token_bytes(32)
    first_device = secrets.token_bytes(32)
    second_device = secrets.token_bytes(32)
    store.issue(device_pub=first_device, root_pub=root, daemon_pub=daemon)
    store.issue(device_pub=first_device, root_pub=root, daemon_pub=daemon)
    with pytest.raises(DeviceReloginChallengeCapacityError, match="device"):
        store.issue(device_pub=first_device, root_pub=root, daemon_pub=daemon)
    store.issue(device_pub=second_device, root_pub=root, daemon_pub=daemon)
    with pytest.raises(DeviceReloginChallengeCapacityError, match="capacity"):
        store.issue(
            device_pub=secrets.token_bytes(32),
            root_pub=root,
            daemon_pub=daemon,
        )
    clock["mono"] += 101
    clock["unix"] += 101
    assert store.pending_count() == 0
    store.issue(device_pub=first_device, root_pub=root, daemon_pub=daemon)


def test_concurrent_challenge_consumption_has_exactly_one_winner() -> None:
    store = DeviceReloginChallengeStore()
    device, root, daemon = (secrets.token_bytes(32) for _ in range(3))
    record = store.issue(device_pub=device, root_pub=root, daemon_pub=daemon)
    barrier = threading.Barrier(24)

    def consume() -> bool:
        barrier.wait()
        try:
            store.consume(
                record.challenge_id,
                device_pub=device,
                root_pub=root,
                daemon_pub=daemon,
            )
            return True
        except DeviceReloginChallengeError:
            return False

    with ThreadPoolExecutor(max_workers=24) as executor:
        results = list(executor.map(lambda _index: consume(), range(24)))
    assert results.count(True) == 1
    assert results.count(False) == 23


@pytest.mark.asyncio
async def test_relogin_route_is_one_time_and_handoff_is_device_bound(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, _state, _root, device_private, cert = enrolled_server
    challenge_response = await server.api_setup_device_invite_relogin_challenge(
        _JsonRequest({"cert_b64": encode_b64u(cert)})
    )
    challenge = _response_json(challenge_response)
    assert challenge_response.status == 200
    assert challenge["ok"] is True
    assert challenge_response.headers["Cache-Control"].startswith("no-store")

    proof = decode_b64u_strict(
        challenge["proof_b64"],
        field="proof_b64",
        min_bytes=1,
        max_bytes=512,
    )
    signature = device_private.sign(proof)
    request_body = {
        "cert_b64": encode_b64u(cert),
        "challenge_id": challenge["challenge_id"],
        "sig_b64": encode_b64u(signature),
    }
    success_response = await server.api_setup_device_invite_relogin(
        _JsonRequest(request_body)
    )
    success = _response_json(success_response)
    assert success_response.status == 200
    assert success["ok"] is True
    expected_fp = "sha256:" + hashlib.sha256(
        device_private.public_key().public_bytes_raw()
    ).hexdigest()
    pending = server.peer_rtc._pending_pairings[success["pair_token"]]
    assert pending.fp_hint == expected_fp

    replay_response = await server.api_setup_device_invite_relogin(
        _JsonRequest(request_body)
    )
    assert replay_response.status == 400
    assert _response_json(replay_response)["error"] == (
        "device_invite_relogin_rejected"
    )
    assert len(server.peer_rtc._pending_pairings) == 1


@pytest.mark.asyncio
async def test_relogin_routes_reject_malformed_json_as_no_store_bad_request(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, _state, _root, _device_private, _cert = enrolled_server
    challenge_response = await server.api_setup_device_invite_relogin_challenge(
        _MalformedJsonRequest(None)
    )
    redeem_response = await server.api_setup_device_invite_relogin(
        _MalformedJsonRequest(None)
    )
    for response in (challenge_response, redeem_response):
        assert response.status == 400
        assert _response_json(response)["error"] == "invalid_relogin_request"
        assert response.headers["Cache-Control"].startswith("no-store")


@pytest.mark.asyncio
async def test_bad_signature_consumes_challenge_without_minting_handoff(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, _state, _root, _device_private, cert = enrolled_server
    challenge_response = await server.api_setup_device_invite_relogin_challenge(
        _JsonRequest({"cert_b64": encode_b64u(cert)})
    )
    challenge = _response_json(challenge_response)
    bad_signature = Ed25519PrivateKey.generate().sign(
        decode_b64u_strict(
            challenge["proof_b64"],
            field="proof_b64",
            min_bytes=1,
            max_bytes=512,
        )
    )
    body = {
        "cert_b64": encode_b64u(cert),
        "challenge_id": challenge["challenge_id"],
        "sig_b64": encode_b64u(bad_signature),
    }
    first = await server.api_setup_device_invite_relogin(_JsonRequest(body))
    second = await server.api_setup_device_invite_relogin(_JsonRequest(body))
    assert first.status == second.status == 400
    assert server.peer_rtc._pending_pairings == {}
    assert server._device_relogin_challenges.pending_count() == 0


@pytest.mark.asyncio
async def test_legacy_client_chosen_nonce_proof_is_never_accepted(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, _state, _root, device_private, cert = enrolled_server
    client_nonce = secrets.token_bytes(32)
    response = await server.api_setup_device_invite_relogin(
        _JsonRequest({
            "cert_b64": encode_b64u(cert),
            "nonce_b64": encode_b64u(client_nonce),
            "sig_b64": encode_b64u(device_private.sign(client_nonce)),
        })
    )
    assert response.status == 400
    assert server.peer_rtc._pending_pairings == {}


@pytest.mark.asyncio
async def test_challenge_rejects_revoked_device_and_never_allocates(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, state, root, device_private, cert = enrolled_server
    state.revoke_self_mesh_device(
        root_pub=root.root_pub,
        device_pub=device_private.public_key().public_bytes_raw(),
    )
    response = await server.api_setup_device_invite_relogin_challenge(
        _JsonRequest({"cert_b64": encode_b64u(cert)})
    )
    assert response.status == 400
    assert server._device_relogin_challenges.pending_count() == 0


@pytest.mark.asyncio
async def test_challenge_for_one_cert_cannot_be_redeemed_by_another(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, state, root, _first_private, first_cert = enrolled_server
    second_private = Ed25519PrivateKey.generate()
    second_pub = second_private.public_key().public_bytes_raw()
    second_cert = mint_device_cert(
        root_seed=root.root_seed,
        root_pub=root.root_pub,
        device_pub=second_pub,
        device_kind="tablet",
    )
    state.upsert_self_mesh_device(
        root_pub=root.root_pub,
        device_pub=second_pub,
        cert=second_cert,
        device_kind="tablet",
        label="Tablet",
        trusted=True,
    )
    challenge_response = await server.api_setup_device_invite_relogin_challenge(
        _JsonRequest({"cert_b64": encode_b64u(first_cert)})
    )
    challenge = _response_json(challenge_response)
    signature = second_private.sign(
        decode_b64u_strict(
            challenge["proof_b64"],
            field="proof_b64",
            min_bytes=1,
            max_bytes=512,
        )
    )
    response = await server.api_setup_device_invite_relogin(
        _JsonRequest({
            "cert_b64": encode_b64u(second_cert),
            "challenge_id": challenge["challenge_id"],
            "sig_b64": encode_b64u(signature),
        })
    )
    assert response.status == 400
    assert server._device_relogin_challenges.pending_count() == 0
    assert server.peer_rtc._pending_pairings == {}


def _install_setup_invite(server: UIServer, root: MeshRoot) -> str:
    token = secrets.token_urlsafe(32)
    now_ms = time.time_ns() // 1_000_000
    server._setup_device_invites[token] = {
        "root_pub": root.root_pub,
        "root_seed": root.root_seed,
        "label": "Add device",
        "created_ms": now_ms,
        "expires_ms": now_ms + 30 * 60 * 1000,
        "claimed": False,
    }
    return token


def _claim_body(
    token: str,
    device_private: Ed25519PrivateKey,
    *,
    kind: str = "phone-ios",
    label: str = "Personal phone",
) -> dict[str, str]:
    return {
        "token": token,
        "device_pub_b64": encode_b64u(
            device_private.public_key().public_bytes_raw()
        ),
        "device_kind": kind,
        "label": label,
    }


@pytest.mark.asyncio
async def test_setup_invite_exact_claim_replay_is_idempotent_and_not_reaudited(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, state, root, device_private, _cert = enrolled_server
    token = _install_setup_invite(server, root)
    body = _claim_body(token, device_private)

    first = await server.api_setup_device_invite_claim(_JsonRequest(body))
    second = await server.api_setup_device_invite_claim(_JsonRequest(dict(body)))
    first_payload = _response_json(first)
    second_payload = _response_json(second)

    assert first.status == second.status == 200
    assert first_payload["idempotent_replay"] is False
    assert second_payload["idempotent_replay"] is True
    assert second_payload["claimed_ms"] == first_payload["claimed_ms"]
    assert second_payload["trust_code"] == first_payload["trust_code"]
    device_pub = device_private.public_key().public_bytes_raw()
    invite_secret = decode_b64u_strict(
        token, field="token", exact_bytes=32, max_bytes=32,
    )
    expected_words = compute_setup_sas_words(
        root.root_pub,
        device_pub,
        invite_secret=invite_secret,
    )
    assert first_payload["sas_version"] == "setup-words-v1"
    assert first_payload["trust_words"] == list(expected_words)
    assert first_payload["trust_phrase"] == format_sas_words(expected_words)
    assert first_payload["trust_code"] == first_payload["trust_phrase"]
    assert first_payload["compatibility_code"] != first_payload["trust_phrase"]
    pending = server._setup_device_invites[token]["pending_claim"]
    assert pending["device_pub"] == device_private.public_key().public_bytes_raw()
    events = [
        row
        for row in state.list_self_mesh_audit(limit=20)
        if row["event"] == "setup_device_invite_pending"
    ]
    assert len(events) == 1


@pytest.mark.asyncio
async def test_setup_invite_requires_five_word_authority_not_numeric_compatibility(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, _state, root, device_private, _cert = enrolled_server
    token = _install_setup_invite(server, root)
    claim_response = await server.api_setup_device_invite_claim(
        _JsonRequest(_claim_body(token, device_private))
    )
    claim = _response_json(claim_response)

    rejected = await server.api_setup_device_invite_confirm(_JsonRequest({
        "token": token,
        "sas": claim["compatibility_code"],
    }))
    assert rejected.status == 400
    assert "mismatch" in _response_json(rejected)["hint"].lower()
    assert server._setup_device_invites[token].get("confirmed") is not True

    accepted = await server.api_setup_device_invite_confirm(_JsonRequest({
        "token": token,
        "sas": claim["trust_phrase"],
    }))
    assert accepted.status == 200
    assert server._setup_device_invites[token]["confirmed"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["device", "kind", "label"])
async def test_setup_invite_claim_cannot_be_mutated_after_first_owner(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
    mutation: str,
) -> None:
    server, _state, root, device_private, _cert = enrolled_server
    token = _install_setup_invite(server, root)
    original = _claim_body(token, device_private)
    first = await server.api_setup_device_invite_claim(_JsonRequest(original))
    assert first.status == 200
    original_pending = dict(server._setup_device_invites[token]["pending_claim"])

    changed = dict(original)
    if mutation == "device":
        changed["device_pub_b64"] = encode_b64u(
            Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        )
    elif mutation == "kind":
        changed["device_kind"] = "tablet"
    else:
        changed["label"] = "Attacker replacement"
    rejected = await server.api_setup_device_invite_claim(_JsonRequest(changed))

    assert rejected.status == 400
    assert "already claimed" in _response_json(rejected)["hint"]
    assert server._setup_device_invites[token]["pending_claim"] == original_pending


@pytest.mark.asyncio
async def test_concurrent_same_claim_has_one_owner_and_idempotent_replays(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, state, root, device_private, _cert = enrolled_server
    token = _install_setup_invite(server, root)
    body = _claim_body(token, device_private)
    responses = await asyncio.gather(
        *(
            server.api_setup_device_invite_claim(_JsonRequest(dict(body)))
            for _index in range(16)
        )
    )
    payloads = [_response_json(response) for response in responses]
    assert all(response.status == 200 for response in responses)
    assert sum(payload["idempotent_replay"] is False for payload in payloads) == 1
    assert sum(payload["idempotent_replay"] is True for payload in payloads) == 15
    assert len({payload["trust_code"] for payload in payloads}) == 1
    assert len({payload["claimed_ms"] for payload in payloads}) == 1
    events = [
        row
        for row in state.list_self_mesh_audit(limit=20)
        if row["event"] == "setup_device_invite_pending"
    ]
    assert len(events) == 1


@pytest.mark.asyncio
async def test_concurrent_different_claimants_cannot_overwrite_winner(
    enrolled_server: tuple[UIServer, State, MeshRoot, Ed25519PrivateKey, bytes],
) -> None:
    server, _state, root, first_private, _cert = enrolled_server
    token = _install_setup_invite(server, root)
    second_private = Ed25519PrivateKey.generate()
    contenders = (
        _claim_body(token, first_private, label="First"),
        _claim_body(token, second_private, label="Second"),
    )
    responses = await asyncio.gather(
        *(server.api_setup_device_invite_claim(_JsonRequest(body)) for body in contenders)
    )
    assert sorted(response.status for response in responses) == [200, 400]
    winner_index = next(
        index for index, response in enumerate(responses) if response.status == 200
    )
    winner_pub = decode_b64u_strict(
        contenders[winner_index]["device_pub_b64"],
        field="device_pub_b64",
        exact_bytes=32,
        max_bytes=32,
    )
    pending = server._setup_device_invites[token]["pending_claim"]
    assert pending["device_pub"] == winner_pub
    assert pending["label"] == contenders[winner_index]["label"]

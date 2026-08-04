"""v0.7.1 deny-by-default capability policy tests.

Pin the security audit's finding A:
  - SAS-pair finalize installs `policy=[CHAT]` so files/folders/groups
    require an explicit user grant. Existing legacy semantics
    (`policy is None → allow`) are preserved for backward compat.
  - Capability denial fires a `capability_request` WS event so the UI
    can show a one-click Allow prompt.
  - Repeat denials within a dedup window do not spam the UI.
  - The /api/peers/{fp}/capabilities/grant + /revoke endpoints
    add/remove a single capability and audit the change.
  - Sharing a folder with a peer auto-adds folder/merkle caps.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.capabilities import (
    CHAT, FILES, FOLDER_SYNC, MERKLE_SYNC,
    DEFAULT_ALLOW_AFTER_PAIRING, PROMPT_REQUIRED,
    LOCAL_CAPABILITIES,
)
from one_link.daemon import (
    CAPABILITY_REQUEST_DEDUP_S,
    Daemon,
)
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg, make_msg


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


class _FakeChannel:
    def __init__(self, *, peer_ed_pub: bytes, peer_short_id: str):
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps: dict | None = None
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        raise NotImplementedError

    async def close(self) -> None:
        pass


# ─── capability constants ──────────────────────────────────────────

def test_default_allow_includes_chat_only():
    assert CHAT in DEFAULT_ALLOW_AFTER_PAIRING
    assert FILES not in DEFAULT_ALLOW_AFTER_PAIRING
    assert FOLDER_SYNC not in DEFAULT_ALLOW_AFTER_PAIRING


def test_prompt_required_covers_sensitive_caps():
    assert FILES in PROMPT_REQUIRED
    assert FOLDER_SYNC in PROMPT_REQUIRED
    assert MERKLE_SYNC in PROMPT_REQUIRED
    assert CHAT not in PROMPT_REQUIRED


def test_default_allow_and_prompt_are_disjoint():
    assert not (set(DEFAULT_ALLOW_AFTER_PAIRING) & set(PROMPT_REQUIRED))


def test_default_allow_plus_prompt_covers_user_facing_local_caps():
    """Every USER-FACING capability we advertise must be classified
    as either auto-allow-on-pair or prompt-required. Transport-layer
    capabilities (e.g. double_ratchet_v1) are negotiated between
    channels and don't appear in either bucket."""
    from one_link.capabilities import TRANSPORT_LAYER_CAPS
    user_caps = set(LOCAL_CAPABILITIES) - set(TRANSPORT_LAYER_CAPS)
    union = set(DEFAULT_ALLOW_AFTER_PAIRING) | set(PROMPT_REQUIRED)
    assert user_caps == union


# ─── _apply_default_capability_policy ──────────────────────────────

def test_apply_default_policy_allow_all_when_setting_unset(tmp_path: Path):
    """The product default is allow-all after SAS verification. With
    pair_default_allow_all unset, pairing leaves policy=None so chat,
    files, folders, voice, and video Just Work for a verified device."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    daemon._apply_default_capability_policy(them.fingerprint)
    policy = state.get_peer_capability_policy(them.fingerprint)
    assert policy is None
    state.close()


def test_apply_default_policy_allow_all_when_setting_true(tmp_path: Path):
    """v0.20.7: when the user explicitly sets pair_default_allow_all
    to true, SAS-pair finalize leaves policy=None (legacy allow-all
    behavior). This is the opt-in escape hatch — never the default."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.set_setting("pair_default_allow_all", "true")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    daemon._apply_default_capability_policy(them.fingerprint)
    policy = state.get_peer_capability_policy(them.fingerprint)
    assert policy is None
    state.close()


def test_apply_default_policy_strict_when_setting_off(tmp_path: Path):
    """When pair_default_allow_all is explicitly set to false, the
    v0.7.2 audit-finding-A behavior applies: policy=[CHAT] only.
    Same outcome as the new default; this test pins the explicit
    opt-in path independently."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.set_setting("pair_default_allow_all", "false")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    daemon._apply_default_capability_policy(them.fingerprint)
    policy = state.get_peer_capability_policy(them.fingerprint)
    assert policy == list(DEFAULT_ALLOW_AFTER_PAIRING)
    state.close()


def test_apply_default_policy_does_not_overwrite_existing(tmp_path: Path):
    """If the user already configured a policy, pairing shouldn't
    blow it away."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_capability_policy(
        them.fingerprint, [CHAT, FILES], actor="ui-pre-pair",
    )

    daemon._apply_default_capability_policy(them.fingerprint)
    policy = state.get_peer_capability_policy(them.fingerprint)
    assert policy == [CHAT, FILES]  # unchanged
    state.close()


def test_apply_default_policy_records_audit_when_strict(tmp_path: Path):
    """Audit row only fires when strict mode is active (it's the
    one path that actually writes a policy). With allow-all
    default, no policy is written so no audit row should appear."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.set_setting("pair_default_allow_all", "false")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    daemon._apply_default_capability_policy(them.fingerprint)
    audit = state.recent_capability_audit(fingerprint=them.fingerprint, limit=5)
    assert audit, "audit row not recorded"
    assert audit[0]["kind"] == "cap_policy_set"
    assert audit[0]["actor"] == "pairing"
    assert "deny-by-default" in (audit[0].get("note") or "")
    state.close()


# ─── _capability_allowed semantics ─────────────────────────────────

def test_capability_allowed_legacy_none_policy_allows_everything(tmp_path: Path):
    """Pre-v0.7.1 behavior: if no policy is set, every cap allowed.
    This preserves the UX for peers paired before the upgrade."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    # No policy set.
    assert daemon._capability_allowed(them.fingerprint, FILES) is True
    assert daemon._capability_allowed(them.fingerprint, FOLDER_SYNC) is True
    state.close()


@pytest.mark.parametrize("trust", ["pending", "rejected"])
def test_legacy_none_policy_never_authorizes_unpaired_peer(
    tmp_path: Path, trust: str,
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, trust)

    assert state.get_peer_capability_policy(them.fingerprint) is None
    assert daemon._capability_allowed(them.fingerprint, CHAT) is False
    assert daemon._capability_allowed(them.fingerprint, FILES) is False
    state.close()


def test_legacy_none_policy_never_authorizes_unknown_peer(tmp_path: Path):
    daemon = Daemon(_new_identity())
    daemon.state = State(db_path=tmp_path / "s.db")

    assert daemon._capability_allowed("f" * 64, CHAT) is False
    assert daemon._capability_allowed("f" * 64, FILES) is False
    daemon.state.close()


def test_capability_allowed_strict_policy_after_pair_when_setting_off(
    tmp_path: Path,
):
    """When pair_default_allow_all=false (opt-in strict), SAS-pair
    finalize sets policy=[CHAT]; FILES/FOLDER_SYNC are denied until
    the user explicitly grants them in the device drawer."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.set_setting("pair_default_allow_all", "false")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._apply_default_capability_policy(them.fingerprint)

    assert daemon._capability_allowed(them.fingerprint, CHAT) is True
    assert daemon._capability_allowed(them.fingerprint, FILES) is False
    assert daemon._capability_allowed(them.fingerprint, FOLDER_SYNC) is False
    state.close()


# ─── _emit_capability_request rate-limit ───────────────────────────

def test_emit_capability_request_broadcasts_once(tmp_path: Path):
    me = _new_identity()
    daemon = Daemon(me)
    events: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=lambda evt: events.append(evt))

    daemon._emit_capability_request("aa" * 32, "abc12345", FILES)
    assert len(events) == 1
    assert events[0]["type"] == "capability_request"
    assert events[0]["fingerprint"] == "aa" * 32
    assert events[0]["short_id"] == "abc12345"
    assert events[0]["capability"] == FILES
    assert isinstance(events[0]["ts_ms"], int)


def test_emit_capability_request_dedups_within_window(tmp_path: Path):
    me = _new_identity()
    daemon = Daemon(me)
    events: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=lambda evt: events.append(evt))

    for _ in range(10):
        daemon._emit_capability_request("aa" * 32, "abc12345", FILES)
    assert len(events) == 1


def test_emit_capability_request_distinct_caps_independent(tmp_path: Path):
    me = _new_identity()
    daemon = Daemon(me)
    events: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=lambda evt: events.append(evt))

    daemon._emit_capability_request("aa" * 32, "x", FILES)
    daemon._emit_capability_request("aa" * 32, "x", FOLDER_SYNC)
    assert len(events) == 2
    assert {e["capability"] for e in events} == {FILES, FOLDER_SYNC}


def test_emit_capability_request_no_ui_server_is_safe():
    me = _new_identity()
    daemon = Daemon(me)
    daemon.ui_server = None
    before = dict(getattr(daemon, "_capability_request_seen", {}))

    daemon._emit_capability_request("aa" * 32, "abc", FILES)

    # "Does not raise" cannot catch the failure that matters here. The early
    # return sits ABOVE the dedup bookkeeping on purpose: if it ever moved
    # below, a peer could burn its 5-prompts-per-60s budget while no UI is
    # attached, and the first genuine prompt after the user opens the UI would
    # be dropped as a duplicate. So assert the rate-limit state is untouched.
    assert dict(getattr(daemon, "_capability_request_seen", {})) == before, (
        "a prompt with no UI attached consumed dedup state; a later real "
        "request for the same capability would now be suppressed"
    )
    assert not getattr(daemon, "_capability_request_per_peer", {}), (
        "a per-peer prompt window was opened for a prompt that was never shown"
    )

    # CONTROL: with a UI attached the same call DOES record state. Without
    # this, the two assertions above would pass just as well against a method
    # that never records anything at all, and would be measuring nothing.
    attached = Daemon(_new_identity())
    attached.ui_server = SimpleNamespace(broadcast=lambda evt: None)
    attached._emit_capability_request("aa" * 32, "abc", FILES)
    assert getattr(attached, "_capability_request_seen", {}), (
        "the control did not record dedup state, so the no-UI assertions "
        "above cannot distinguish a no-op from a broken method"
    )


def test_emit_capability_request_dedup_window_is_sane():
    """The dedup window should be >0 (it's a real lock-out) and <5min
    (a stale window would block legit re-requests after revoke/re-grant)."""
    assert 0 < CAPABILITY_REQUEST_DEDUP_S < 300


# ─── grant / revoke server endpoints ───────────────────────────────

@pytest.mark.asyncio
async def test_api_grant_capability_adds_cap(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes, trust_default="pinned",
    )
    state.set_peer_capability_policy(them.fingerprint, [CHAT])

    broadcasts: list[dict] = []
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: broadcasts.append(evt)

    class _Req:
        match_info = {"fp": them.fingerprint}
        async def json(self):
            return {"cap": FILES, "note": "user clicked Allow"}

    resp = await server.api_grant_capability(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["added"] is True
    assert FILES in body["allowed"]
    assert CHAT in body["allowed"]

    # Persisted
    assert FILES in state.get_peer_capability_policy(them.fingerprint)
    # Broadcast fired
    assert any(b.get("type") == "peer_capabilities" for b in broadcasts)
    state.close()


@pytest.mark.asyncio
async def test_api_grant_capability_idempotent(tmp_path: Path):
    from one_link.server import UIServer

    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_capability_policy(them.fingerprint, [CHAT, FILES])

    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": them.fingerprint}
        async def json(self):
            return {"cap": FILES}

    resp = await server.api_grant_capability(_Req())
    body = json.loads(resp.text)
    assert body["added"] is False
    state.close()


@pytest.mark.asyncio
async def test_api_grant_capability_rejects_unknown_cap(tmp_path: Path):
    from one_link.server import UIServer

    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": them.fingerprint}
        async def json(self):
            return {"cap": "bogus"}

    resp = await server.api_grant_capability(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_revoke_capability_removes_cap(tmp_path: Path):
    from one_link.server import UIServer

    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_capability_policy(them.fingerprint, [CHAT, FILES])

    broadcasts: list[dict] = []
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: broadcasts.append(evt)

    class _Req:
        match_info = {"fp": them.fingerprint}
        async def json(self):
            return {"cap": FILES}

    resp = await server.api_revoke_capability(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["removed"] is True
    assert FILES not in body["allowed"]
    assert CHAT in body["allowed"]
    assert FILES not in state.get_peer_capability_policy(them.fingerprint)
    assert any(b.get("type") == "peer_capabilities" for b in broadcasts)
    state.close()


@pytest.mark.asyncio
async def test_api_revoke_capability_idempotent_when_not_present(tmp_path: Path):
    from one_link.server import UIServer

    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_capability_policy(them.fingerprint, [CHAT])

    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": them.fingerprint}
        async def json(self):
            return {"cap": FILES}

    resp = await server.api_revoke_capability(_Req())
    body = json.loads(resp.text)
    assert body["removed"] is False
    state.close()


# ─── deny path emits prompt event end-to-end ───────────────────────

@pytest.mark.asyncio
async def test_file_offer_deny_emits_capability_request(tmp_path: Path):
    """The full v0.7.1 contract: a paired-but-not-cap-granted peer
    sending FILE_OFFER must (a) get rejected, (b) trigger a UI prompt."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    state.set_peer_capability_policy(them.fingerprint, [CHAT])

    events: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=lambda evt: events.append(evt))

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    offer = make_msg(
        "FILE_OFFER", them.short_id,
        name="x.bin", size=10, blob="00" * 32, chunks=[], mode="cdc",
    )
    await daemon._on_peer_message(chan, offer)

    # ACK with rejection sent
    rejects = [s for s in chan.sent if s.get("rejected")]
    assert rejects, f"no rejection ACK sent; sent={chan.sent}"
    assert rejects[0]["rejected"] == "capability_disabled"

    # WS event broadcast
    requests = [e for e in events if e.get("type") == "capability_request"]
    assert requests, f"no capability_request broadcast; events={events}"
    assert requests[0]["capability"] == FILES
    assert requests[0]["fingerprint"] == them.fingerprint
    state.close()


# ─── share folder auto-grants folder caps ──────────────────────────

@pytest.mark.asyncio
async def test_share_folder_auto_grants_folder_caps(tmp_path: Path):
    """Sharing a folder is positive consent — the user just clicked
    Share. Folder/merkle caps should be auto-added."""
    from one_link.server import UIServer

    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_capability_policy(them.fingerprint, [CHAT])

    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    server._ensure_folder_caps_for(them.fingerprint, note="test")
    policy = state.get_peer_capability_policy(them.fingerprint)
    assert FOLDER_SYNC in policy
    assert MERKLE_SYNC in policy
    assert CHAT in policy
    state.close()


@pytest.mark.asyncio
async def test_ensure_folder_caps_for_materializes_consent_on_legacy_none(tmp_path: Path):
    """2026-05-22 audit Batch T: even for default-allow-all (legacy)
    peers, explicit user share = positive consent. Materialize the
    policy row with FOLDER_SYNC + MERKLE_SYNC so that a future
    strict-mode flip preserves what the user actually shared.

    Previously this returned early, leaving policy=None, which
    silently dropped the explicit-share consent on a strict-mode
    flip (folder shares disappeared from the user's perspective)."""
    from one_link.server import UIServer

    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    # No policy set → legacy mode.
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    server._ensure_folder_caps_for(them.fingerprint, note="test")
    policy = state.get_peer_capability_policy(them.fingerprint)
    # Consent is now durable.
    assert policy is not None
    assert FOLDER_SYNC in policy
    assert MERKLE_SYNC in policy
    state.close()


# ─── no UI server is fine for headless daemons ─────────────────────

def test_apply_default_policy_with_no_state_is_noop():
    me = _new_identity()
    daemon = Daemon(me)
    daemon.state = None

    daemon._apply_default_capability_policy("aa" * 32)

    # The name claims a no-op, so check it is one. Asserting only "did not
    # raise" would pass just as happily if this lazily opened a store and
    # wrote a policy into it -- which for a deny-by-default control would
    # mean installing a grant nobody asked for.
    assert daemon.state is None, (
        "a headless daemon opened a state store while applying default policy"
    )

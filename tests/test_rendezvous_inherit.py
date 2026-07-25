"""Tests for v0.5.4 — zero-step rendezvous bootstrap.

Three inheritance paths, all tested here:
  1. Pair-time URL inheritance (CAPS frame carries `share_rdz`):
     - Pinned peer with URLs in CAPS → we adopt
     - Pending peer (not pinned) → ignored
     - Same peer twice in one session → only adopted once (no spam)
     - Local opt-out (inherit_rendezvous=false) → ignored
     - URLs that fail validation (non-http) → ignored
  2. mDNS-LAN inheritance (rendezvous_urls in mDNS TXT):
     - Empty local config + LAN peer advertises → we adopt
     - Local config already populated → we DON'T overwrite
  3. First-run defaults (env var + seeds.toml + baked-in constant):
     - Env var picked up
     - seeds.toml picked up
     - baked-in constant picked up
     - all three combined, deduped

Plus: CAPS frame embeds `share_rdz` only when local share_rendezvous
is on, and only with pinned-peer-relevant cap.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import (
    Daemon,
    MAX_SHARED_RENDEZVOUS_URLS,
    PROTOCOL_VERSION,
    _build_caps,
)
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


# ─── _build_caps embeds share_rdz when URLs given ───────────────────

def test_build_caps_omits_share_rdz_when_no_urls():
    caps = _build_caps("abcd1234")
    assert "share_rdz" not in caps
    assert caps["protocol"] == PROTOCOL_VERSION


def test_build_caps_includes_share_rdz_with_urls():
    caps = _build_caps("abcd1234", rendezvous_urls=["https://r.example"])
    assert caps["share_rdz"] == ["https://r.example"]


def test_build_caps_caps_share_rdz_at_max():
    too_many = [f"https://h{i}.example" for i in range(MAX_SHARED_RENDEZVOUS_URLS + 5)]
    caps = _build_caps("abcd1234", rendezvous_urls=too_many)
    assert len(caps["share_rdz"]) == MAX_SHARED_RENDEZVOUS_URLS


# ─── _build_my_caps reads state ─────────────────────────────────────

def test_build_my_caps_includes_state_urls_when_share_on(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_rendezvous_urls(["https://r.example"])
        # share_rendezvous default = True (None means True)
        daemon = Daemon(me)
        daemon.state = state
        caps = daemon._build_my_caps()
        assert caps["share_rdz"] == ["https://r.example"]
    finally:
        state.close()


def test_build_my_caps_omits_share_rdz_when_share_off(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_rendezvous_urls(["https://r.example"])
        state.set_setting("share_rendezvous", "false")
        daemon = Daemon(me)
        daemon.state = state
        caps = daemon._build_my_caps()
        assert "share_rdz" not in caps
    finally:
        state.close()


# ─── inherit_rendezvous_urls_from: pinned-only, validated, single-shot ──

def test_inherit_only_from_pinned_peer(tmp_path: Path):
    me = _new_identity()
    peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint, short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        # NOT pinning peer.

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None

        daemon._inherit_rendezvous_urls_from(
            peer.fingerprint, ["https://r.example"]
        )
        # Peer wasn't pinned → no adoption.
        assert state.get_rendezvous_urls() == []
    finally:
        state.close()


def test_inherit_from_pinned_peer_writes_state(tmp_path: Path):
    me = _new_identity()
    peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint, short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None

        daemon._inherit_rendezvous_urls_from(
            peer.fingerprint, ["https://r.example", "https://r2.example"]
        )
        assert sorted(state.get_rendezvous_urls()) == [
            "https://r.example", "https://r2.example",
        ]
    finally:
        state.close()


def test_inherit_dedupes_against_existing_urls(tmp_path: Path):
    me = _new_identity()
    peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint, short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")
        state.set_rendezvous_urls(["https://existing.example"])

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None

        # Offer one new + one already-present.
        daemon._inherit_rendezvous_urls_from(peer.fingerprint, [
            "https://existing.example",
            "https://new.example",
        ])
        assert sorted(state.get_rendezvous_urls()) == [
            "https://existing.example", "https://new.example",
        ]
    finally:
        state.close()


def test_inherit_drops_invalid_urls(tmp_path: Path):
    me = _new_identity()
    peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint, short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None

        daemon._inherit_rendezvous_urls_from(peer.fingerprint, [
            "ws://bad-protocol.example",
            "ftp://nope",
            "https://good.example",
            "",
        ])
        assert state.get_rendezvous_urls() == ["https://good.example"]
    finally:
        state.close()


def test_inherit_respects_local_opt_out(tmp_path: Path):
    me = _new_identity()
    peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint, short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")
        state.set_setting("inherit_rendezvous", "false")

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None

        daemon._inherit_rendezvous_urls_from(
            peer.fingerprint, ["https://r.example"]
        )
        # User opted out — no adoption.
        assert state.get_rendezvous_urls() == []
    finally:
        state.close()


def test_inherit_caps_at_max_shared_urls(tmp_path: Path):
    me = _new_identity()
    peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint, short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None

        too_many = [f"https://h{i}.example" for i in range(MAX_SHARED_RENDEZVOUS_URLS + 10)]
        daemon._inherit_rendezvous_urls_from(peer.fingerprint, too_many)
        urls = state.get_rendezvous_urls()
        assert len(urls) == MAX_SHARED_RENDEZVOUS_URLS
    finally:
        state.close()


def test_inherit_remembers_seen_peers_in_session(tmp_path: Path):
    """Same peer offering URLs twice in one session — second offer is
    a no-op, doesn't re-fire side-effects (UI broadcast, log spam)."""
    me = _new_identity()
    peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=peer.fingerprint, short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None

        daemon._inherit_rendezvous_urls_from(peer.fingerprint, ["https://a.example"])
        daemon._inherit_rendezvous_urls_from(peer.fingerprint, ["https://b.example"])
        # Only the first call took effect.
        assert state.get_rendezvous_urls() == ["https://a.example"]
        assert peer.fingerprint in daemon._inherited_rdz_from
    finally:
        state.close()


# ─── mDNS-LAN inheritance ───────────────────────────────────────────

def test_mdns_inherit_disabled_by_default(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        daemon = Daemon(me)
        daemon.state = state
        peer = Peer(
            short_id="abcd1234", hostname="lan-host", address="192.168.1.10",
            port=51234, ed_pub_hex="11" * 32,
            rendezvous_urls=["https://shared.example"],
        )
        daemon.discovery = SimpleNamespace(
            registry=SimpleNamespace(list=lambda: [peer]),
        )

        daemon._maybe_inherit_rendezvous_from_mdns()
        assert state.get_rendezvous_urls() == []
    finally:
        state.close()


def test_mdns_inherit_when_state_is_empty_and_opted_in(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_setting("inherit_rendezvous_from_mdns", "true")
        daemon = Daemon(me)
        daemon.state = state
        # Mock discovery with one LAN peer advertising rendezvous URL.
        peer = Peer(
            short_id="abcd1234", hostname="lan-host", address="192.168.1.10",
            port=51234, ed_pub_hex="11" * 32,
            rendezvous_urls=["https://shared.example"],
        )
        daemon.discovery = SimpleNamespace(
            registry=SimpleNamespace(list=lambda: [peer]),
        )

        daemon._maybe_inherit_rendezvous_from_mdns()
        assert state.get_rendezvous_urls() == ["https://shared.example"]
    finally:
        state.close()


def test_mdns_inherit_does_not_overwrite_existing(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_rendezvous_urls(["https://my-own.example"])

        daemon = Daemon(me)
        daemon.state = state
        peer = Peer(
            short_id="abcd1234", hostname="lan-host", address="192.168.1.10",
            port=51234, ed_pub_hex="11" * 32,
            rendezvous_urls=["https://lan-advertised.example"],
        )
        daemon.discovery = SimpleNamespace(
            registry=SimpleNamespace(list=lambda: [peer]),
        )
        daemon._maybe_inherit_rendezvous_from_mdns()
        # User already chose; don't override.
        assert state.get_rendezvous_urls() == ["https://my-own.example"]
    finally:
        state.close()


def test_mdns_inherit_respects_opt_out(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_setting("inherit_rendezvous", "false")
        daemon = Daemon(me)
        daemon.state = state
        peer = Peer(
            short_id="abcd1234", hostname="lan-host", address="192.168.1.10",
            port=51234, ed_pub_hex="11" * 32,
            rendezvous_urls=["https://shared.example"],
        )
        daemon.discovery = SimpleNamespace(
            registry=SimpleNamespace(list=lambda: [peer]),
        )
        daemon._maybe_inherit_rendezvous_from_mdns()
        assert state.get_rendezvous_urls() == []
    finally:
        state.close()


def test_mdns_inherit_drops_invalid_protocols(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_setting("inherit_rendezvous_from_mdns", "true")
        daemon = Daemon(me)
        daemon.state = state
        peer = Peer(
            short_id="abcd1234", hostname="lan-host", address="192.168.1.10",
            port=51234, ed_pub_hex="11" * 32,
            rendezvous_urls=["ws://bad", "https://good.example"],
        )
        daemon.discovery = SimpleNamespace(
            registry=SimpleNamespace(list=lambda: [peer]),
        )
        daemon._maybe_inherit_rendezvous_from_mdns()
        assert state.get_rendezvous_urls() == ["https://good.example"]
    finally:
        state.close()


# ─── first-run default seeds ────────────────────────────────────────

def test_harvest_seeds_picks_up_env_var(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        daemon = Daemon(me)
        daemon.state = state
        with patch.dict(
            "os.environ",
            {"ONE_LINK_RDZ_DEFAULTS": "https://a.example,https://b.example"},
        ):
            urls = daemon._harvest_default_rendezvous_seeds()
        assert "https://a.example" in urls
        assert "https://b.example" in urls
    finally:
        state.close()


def test_harvest_seeds_picks_up_seeds_toml(tmp_path: Path, monkeypatch):
    me = _new_identity()
    # Point data_dir at our tmp_path.
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "seeds.toml").write_text(
        "[rendezvous]\nurls = ['https://from-toml.example']\n",
        encoding="utf-8",
    )
    state = State(db_path=data / "state.db")
    try:
        daemon = Daemon(me)
        daemon.state = state
        # Clear env var so it doesn't leak in.
        with patch.dict("os.environ", {}, clear=False):
            monkeypatch.delenv("ONE_LINK_RDZ_DEFAULTS", raising=False)
            urls = daemon._harvest_default_rendezvous_seeds()
        assert "https://from-toml.example" in urls
    finally:
        state.close()


def test_harvest_seeds_picks_up_baked_in_constant(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        daemon = Daemon(me)
        daemon.state = state
        from one_link import rendezvous_client
        original = list(getattr(rendezvous_client, "DEFAULT_RENDEZVOUS_URLS", []))
        try:
            rendezvous_client.DEFAULT_RENDEZVOUS_URLS = ["https://baked.example"]
            with patch.dict("os.environ", {}, clear=False):
                import os as _os
                _os.environ.pop("ONE_LINK_RDZ_DEFAULTS", None)
                urls = daemon._harvest_default_rendezvous_seeds()
            assert "https://baked.example" in urls
        finally:
            rendezvous_client.DEFAULT_RENDEZVOUS_URLS = original
    finally:
        state.close()


def test_harvest_seeds_dedupes_across_sources(tmp_path: Path, monkeypatch):
    me = _new_identity()
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "seeds.toml").write_text(
        "[rendezvous]\nurls = ['https://shared.example']\n",
        encoding="utf-8",
    )
    state = State(db_path=data / "state.db")
    try:
        daemon = Daemon(me)
        daemon.state = state
        monkeypatch.setenv("ONE_LINK_RDZ_DEFAULTS", "https://shared.example,https://env-only.example")
        from one_link import rendezvous_client
        original = list(getattr(rendezvous_client, "DEFAULT_RENDEZVOUS_URLS", []))
        try:
            rendezvous_client.DEFAULT_RENDEZVOUS_URLS = [
                "https://shared.example", "https://baked-only.example",
            ]
            urls = daemon._harvest_default_rendezvous_seeds()
        finally:
            rendezvous_client.DEFAULT_RENDEZVOUS_URLS = original
        assert urls.count("https://shared.example") == 1
        assert "https://env-only.example" in urls
        assert "https://baked-only.example" in urls
    finally:
        state.close()


def test_harvest_seeds_returns_empty_when_nothing_set(tmp_path: Path, monkeypatch):
    """No env, no toml, baked-in empty — empty list. The daemon
    falls back to LAN-only mode silently in this case."""
    me = _new_identity()
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.delenv("ONE_LINK_RDZ_DEFAULTS", raising=False)
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    state = State(db_path=data / "state.db")
    try:
        daemon = Daemon(me)
        daemon.state = state
        urls = daemon._harvest_default_rendezvous_seeds()
        assert urls == []
    finally:
        state.close()

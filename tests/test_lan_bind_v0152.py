"""v0.15.2 — LAN bind via ONE_LINK_BIND_HOST + --lan flag.

Ship-spec from `docs/PHONE_TIER.md` testing-on-real-device path:

  Reach:  users running `one-link app --lan` get the UI served on
          0.0.0.0:7117 instead of 127.0.0.1:7117 so a phone on
          the same Wi-Fi can reach it. The launcher prints the
          non-secret pairing landing URL; the owner token is never printed
          into a LAN URL.
  Hide:   default behavior is unchanged. Without --lan or the env
          var, the daemon binds loopback-only — historical safe
          default. Existing users see no change.
  Async:  none — sync wiring only.
  Depth:  the launcher detects whether an already-running daemon
          is loopback-bound and replaces it when --lan is passed.
          A LAN-mode warning is printed loud and yellow because
           the trust boundary changed, while owner auth stays local/HTTPS.

Tests cover the env-var bind change, default loopback, --lan
flag wiring through CLI to env var, LAN-IP detection, and the
loud-warning print.
"""

from __future__ import annotations

import os
import json
from pathlib import Path

import pytest
import pytest_asyncio
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
        fingerprint=fp, short_id=fp[:8], hostname="lan-host",
    )


@pytest_asyncio.fixture
async def server_default(tmp_path: Path, monkeypatch):
    """A UIServer with no ONE_LINK_BIND_HOST set — should bind loopback."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.delenv("ONE_LINK_BIND_HOST", raising=False)
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()
        state.close()


@pytest_asyncio.fixture
async def server_lan(tmp_path: Path, monkeypatch):
    """A UIServer with ONE_LINK_BIND_HOST=0.0.0.0 — should bind any-iface."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setenv("ONE_LINK_BIND_HOST", "0.0.0.0")
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()
        state.close()


# ───────── env var changes the bind ─────────────────────────────────

@pytest.mark.asyncio
async def test_default_binds_loopback(server_default):
    """No env var → 127.0.0.1 (the historical safe default).
    `bind_host` reflects what was actually bound."""
    assert server_default.bind_host == "127.0.0.1"


@pytest.mark.asyncio
async def test_env_var_binds_any_interface(server_lan):
    """ONE_LINK_BIND_HOST=0.0.0.0 → bind to any interface."""
    assert server_lan.bind_host == "0.0.0.0"


@pytest.mark.asyncio
async def test_status_reports_actual_bind_host(server_lan):
    """Status reports the active bind host so launchers and diagnostics
    can tell LAN mode from loopback mode without guessing."""
    resp = await server_lan.api_status(None)  # type: ignore[arg-type]
    assert resp.status == 200
    body = json.loads(resp.text)
    assert body["bind_host"] == "0.0.0.0"


def test_setup_invite_peer_url_uses_lan_ip_when_lan_bound(server_lan, monkeypatch):
    """A QR minted from the desktop UI is requested over 127.0.0.1,
    but the encoded phone URL must use the reachable LAN address."""
    from one_link import server as server_mod

    class Req:
        scheme = "http"
        host = f"127.0.0.1:{server_lan.port}"

    monkeypatch.setattr(server_mod, "_detect_lan_ip", lambda: "192.168.1.142")
    server_lan.https_port = server_lan.port + 1
    assert (
        server_lan._setup_invite_peer_url(Req(), "tok")
        == f"http://192.168.1.142:{server_lan.port}/connect?token=tok"
    )


@pytest.mark.asyncio
async def test_socket_actually_listens_on_lan_iface(server_lan):
    """A 0.0.0.0 bind MUST be reachable from a non-loopback IP. Probe
    via the test server's actual sockname — port should be valid +
    bound to the wildcard address (0.0.0.0 or :: depending on stack)."""
    sockets = server_lan.site._server.sockets  # type: ignore[union-attr]
    assert sockets
    bound_addrs = {s.getsockname()[0] for s in sockets}
    # On dual-stack systems the OS may bind to 0.0.0.0 directly. Pin
    # that we are NOT on loopback.
    assert "127.0.0.1" not in bound_addrs


# ───────── --lan flag wires through to env var ──────────────────────

def test_cli_lan_flag_exists():
    """The `--lan` option MUST be registered on the `app` command."""
    from click.testing import CliRunner
    from one_link.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["app", "--help"])
    assert result.exit_code == 0
    assert "--lan" in result.output
    # The help text must mention the trust boundary explicitly.
    assert "Wi-Fi" in result.output or "LAN" in result.output


def test_cli_app_defaults_to_loopback_and_lan_is_explicit(monkeypatch):
    """Desktop owner UI is local by default; --lan is an explicit opt-in."""
    from click.testing import CliRunner
    from one_link.cli import cli

    calls = []

    def fake_run_app(**kwargs):
        calls.append(kwargs)
        return 0

    monkeypatch.setattr("one_link.app.run_app", fake_run_app)
    result = CliRunner().invoke(cli, ["app", "--no-browser"])
    assert result.exit_code == 0
    assert calls[-1]["lan"] is False

    result = CliRunner().invoke(cli, ["app", "--no-browser", "--lan"])
    assert result.exit_code == 0
    assert calls[-1]["lan"] is True


def test_run_app_sets_env_var_when_lan_passed(monkeypatch):
    """When run_app is called with lan=True, ONE_LINK_BIND_HOST MUST
    be set to 0.0.0.0 BEFORE any daemon spawn so the spawned
    subprocess inherits the right value.

    Cleans up the env var explicitly via try/finally because run_app
    sets it directly on os.environ — monkeypatch.setenv only reverts
    keys IT set, so a direct assignment leaks across tests and
    flips the bind host for unrelated server fixtures down the
    pytest collection order."""
    from one_link import app as app_mod

    monkeypatch.delenv("ONE_LINK_BIND_HOST", raising=False)
    captured_env = {}

    def fake_resolve():
        # Capture env state at the point of resolution — that's where
        # the launcher decides whether to spawn.
        captured_env["BIND_HOST"] = os.environ.get("ONE_LINK_BIND_HOST")
        # Return None so run_app proceeds to spawn (we'll short-circuit).
        return None

    def fake_spawn():
        # Bail before actually launching a subprocess in the test.
        raise RuntimeError("test-bail")

    monkeypatch.setattr(app_mod, "_resolve_running_daemon", fake_resolve)
    monkeypatch.setattr(app_mod, "_stop_verified_legacy_daemon", lambda: None)
    monkeypatch.setattr(app_mod, "_spawn_daemon", fake_spawn)
    try:
        with pytest.raises(RuntimeError, match="test-bail"):
            app_mod.run_app(no_browser=True, lan=True)
        assert captured_env["BIND_HOST"] == "0.0.0.0"
    finally:
        os.environ.pop("ONE_LINK_BIND_HOST", None)


def test_run_app_forces_loopback_without_lan(monkeypatch):
    """Default launch overwrites a stale ambient LAN bind fail-closed."""
    from one_link import app as app_mod

    monkeypatch.delenv("ONE_LINK_BIND_HOST", raising=False)

    def fake_resolve():
        return None

    def fake_spawn():
        raise RuntimeError("test-bail")

    monkeypatch.setattr(app_mod, "_resolve_running_daemon", fake_resolve)
    monkeypatch.setattr(app_mod, "_stop_verified_legacy_daemon", lambda: None)
    monkeypatch.setattr(app_mod, "_spawn_daemon", fake_spawn)
    with pytest.raises(RuntimeError, match="test-bail"):
        app_mod.run_app(no_browser=True, lan=False)
    assert os.environ["ONE_LINK_BIND_HOST"] == "127.0.0.1"


# ───────── LAN-IP detection ─────────────────────────────────────────

def test_detect_lan_ip_returns_string():
    """Helper MUST return a string — never None or raise. On a
    machine with no usable interface, falls back to 127.0.0.1
    so the caller can decide how to handle that gracefully."""
    from one_link.app import _detect_lan_ip

    ip = _detect_lan_ip()
    assert isinstance(ip, str)
    assert ip
    # IPv4 dotted quad sanity.
    parts = ip.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def test_detect_lan_ip_falls_back_when_socket_fails(monkeypatch):
    """When the UDP-connect probe fails (airplane mode, no DNS,
    socket library disabled), the helper MUST fall back to 127.0.0.1
    instead of raising."""
    from one_link import app as app_mod

    class ExplodingSocket:
        def __init__(self, *_args, **_kwargs):
            pass
        def connect(self, *_args, **_kwargs):
            raise OSError("network down")
        def getsockname(self):
            raise OSError("never reached")
        def close(self):
            pass

    monkeypatch.setattr(app_mod.socket, "socket", lambda *a, **kw: ExplodingSocket())
    assert app_mod._detect_lan_ip() == "127.0.0.1"


# ───────── LAN warning print ────────────────────────────────────────

def test_print_lan_warning_via_capsys(capsys):
    """LAN warning prints pairing reachability but no owner credential."""
    from one_link.app import _print_lan_warning

    _print_lan_warning("192.168.1.42", 7117)
    captured = capsys.readouterr()
    assert "192.168.1.42" in captured.out
    assert "7117" in captured.out
    assert "test-token-abc" not in captured.out
    assert "/connect" in captured.out
    # Pin the security copy so a refactor can't quietly soften it.
    assert "LAN MODE" in captured.out
    assert "plain LAN HTTP" in captured.out
    assert "short-lived invite" in captured.out


def test_print_lan_warning_is_ascii_only():
    """v0.15.3 regression — the warning print MUST stay ASCII-only.
    Windows consoles default to cp1252 and choke on non-ASCII glyphs
    (the original ⚠ U+26A0 raised UnicodeEncodeError, which crashed
    the launcher AFTER the daemon had already spawned — leaving the
    user with a running daemon but no printed URL). Capture stdout
    via a cp1252-encoded stream and confirm no encode error fires."""
    import io
    import contextlib

    from one_link.app import _print_lan_warning

    # cp1252 is the default Windows console encoding. If the print
    # contains a glyph cp1252 can't represent, this raises.
    buf = io.BytesIO()
    text_buf = io.TextIOWrapper(buf, encoding="cp1252", newline="")
    with contextlib.redirect_stdout(text_buf):
        _print_lan_warning("192.168.1.42", 7117)
        text_buf.flush()
    encoded = buf.getvalue()
    # Sanity: the URL still made it through.
    assert b"192.168.1.42" in encoded
    assert b"LAN MODE" in encoded


# ───────── version pin ──────────────────────────────────────────────

def test_print_lan_warning_ignores_invalid_gui_stdout(monkeypatch):
    """Windowed PyInstaller launches can have an invalid stdout handle.
    Startup status printing must never crash the desktop app."""
    from one_link import app as app_mod

    def bad_echo(*_args, **_kwargs):
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(app_mod.click, "echo", bad_echo)
    monkeypatch.setattr(app_mod.click, "secho", bad_echo)
    app_mod._print_lan_warning("192.168.1.42", 7117)


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

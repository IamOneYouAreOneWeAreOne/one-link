"""Phase 3b: /api/me surfaces autoinstall_enabled, UI shows 'Update now'
button when the gate is on.

Defends the contract that:
    * The 'Update now' button must be invisible when the daemon
      doesn't have ONE_LINK_EXPERIMENTAL_AUTOINSTALL=1 set. If the
      button leaks into the UI without the gate, clicking it just
      shows a 503 — bad UX, but more importantly a footgun for a
      future maintainer who forgets to set the env var.
    * The button MUST be visible when the gate IS on, so the work
      we did in Phase 3 is reachable.
    * /api/me reports the flag honestly. The UI relies on its value.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


WEB_INDEX = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


# ─── /api/me autoinstall_enabled contract ─────────────────────────────

@pytest.mark.asyncio
async def test_api_me_reports_autoinstall_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", raising=False)
    from one_link.server import UIServer

    me_stub = SimpleNamespace(
        short_id="aaaaaaaa",
        fingerprint="aa" * 32,
        hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    daemon = SimpleNamespace(
        state=None, discovery=None, me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)
    resp = await server.api_me(SimpleNamespace(query={}))
    body = json.loads(resp.text)
    assert body["autoinstall_enabled"] is False


@pytest.mark.asyncio
async def test_api_me_reports_autoinstall_enabled_when_env_set(monkeypatch):
    monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", "1")
    from one_link.server import UIServer

    me_stub = SimpleNamespace(
        short_id="aaaaaaaa",
        fingerprint="aa" * 32,
        hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    daemon = SimpleNamespace(
        state=None, discovery=None, me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)
    resp = await server.api_me(SimpleNamespace(query={}))
    body = json.loads(resp.text)
    assert body["autoinstall_enabled"] is True


@pytest.mark.asyncio
async def test_api_me_autoinstall_accepts_truthy_strings(monkeypatch):
    """Standard env-var convention: '1', 'true', 'yes' all enable."""
    from one_link.server import UIServer
    me_stub = SimpleNamespace(
        short_id="aaaaaaaa", fingerprint="aa" * 32, hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    daemon = SimpleNamespace(
        state=None, discovery=None, me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)

    for value in ("1", "true", "yes"):
        monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", value)
        resp = await server.api_me(SimpleNamespace(query={}))
        body = json.loads(resp.text)
        assert body["autoinstall_enabled"] is True, f"value={value!r}"


@pytest.mark.asyncio
async def test_api_me_autoinstall_rejects_falsy_strings(monkeypatch):
    """'0', 'no', 'false', '' all leave the gate off. Anything but
    explicitly truthy keeps the destructive endpoint disabled."""
    from one_link.server import UIServer
    me_stub = SimpleNamespace(
        short_id="aaaaaaaa", fingerprint="aa" * 32, hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    daemon = SimpleNamespace(
        state=None, discovery=None, me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)

    for value in ("0", "no", "false", "", "maybe"):
        monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", value)
        resp = await server.api_me(SimpleNamespace(query={}))
        body = json.loads(resp.text)
        assert body["autoinstall_enabled"] is False, f"value={value!r}"


# ─── UI markup contract ────────────────────────────────────────────────

def test_index_html_has_install_button():
    """The button element exists. JS unhides it conditionally; markup
    is unconditional so the show/hide is reliable."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    assert 'id="update-banner-install"' in html, (
        "Update-now button missing from banner"
    )


def test_install_button_is_hidden_by_default_in_markup():
    """The default inline style hides the button — JS only un-hides
    it when state.me.autoinstall_enabled is true. This prevents the
    button from briefly flashing on load before JS catches up."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    idx = html.find('id="update-banner-install"')
    assert idx > 0
    # Slice the surrounding 200 chars to inspect the inline style.
    snippet = html[idx:idx + 200]
    assert 'style="display:none"' in snippet, (
        "button should be hidden by default to avoid a flash before "
        "JS reads autoinstall_enabled"
    )


def test_check_for_update_consults_autoinstall_flag():
    """The JS that decides whether to show the install button must
    read state.me.autoinstall_enabled. Regression guard against
    accidentally showing the destructive button to non-experimental
    users."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    fn_start = html.find("async function checkForUpdate")
    assert fn_start > 0
    fn_body = html[fn_start:fn_start + 3000]
    assert "autoinstall_enabled" in fn_body, (
        "checkForUpdate doesn't gate on autoinstall_enabled — the "
        "destructive install button would show for everyone"
    )


def test_install_button_calls_install_endpoint():
    """Click handler must POST to /api/update/install (not just
    open a link). Without this, the button is visual noise."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    assert "/api/update/install" in html
    # And it confirms before doing the destructive action.
    assert "confirm(" in html


def test_install_button_handler_is_disabled_during_install():
    """During install the button shouldn't allow a double-click —
    the daemon is shutting down, double-firing would 502."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    # Find the JS handler by its getElementById call (not the HTML
    # element with the same id, which lacks the disabled-true line).
    handler_idx = html.find('getElementById("update-banner-install")')
    assert handler_idx > 0, "JS handler for update-banner-install not found"
    body = html[handler_idx:handler_idx + 2000]
    assert "installBtn.disabled = true" in body, (
        "click handler doesn't disable the button — double-click risk"
    )

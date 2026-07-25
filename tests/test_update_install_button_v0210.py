"""UI capability-truth contracts for executable update handoff.

Defends the contract that:
    * Historical environment/settings opt-ins cannot fabricate capability.
    * The button appears only for a locally validated standalone bundle.
    * The only executable request is an explicit confirmed one-shot install.
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
async def test_api_me_reports_autoinstall_enabled_by_default(monkeypatch):
    """Missing operator and user state fails closed."""
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
async def test_api_me_reports_autoinstall_unavailable_when_env_set(monkeypatch):
    monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", "1")
    from one_link.server import UIServer

    me_stub = SimpleNamespace(
        short_id="aaaaaaaa",
        fingerprint="aa" * 32,
        hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    state = SimpleNamespace(get_setting=lambda key: "1")
    daemon = SimpleNamespace(
        state=state, discovery=None, me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)
    resp = await server.api_me(SimpleNamespace(query={}))
    body = json.loads(resp.text)
    assert body["autoinstall_enabled"] is False


@pytest.mark.asyncio
async def test_api_me_autoinstall_requires_exact_operator_value(monkeypatch):
    from one_link.server import UIServer
    me_stub = SimpleNamespace(
        short_id="aaaaaaaa", fingerprint="aa" * 32, hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    state = SimpleNamespace(get_setting=lambda key: "true")
    daemon = SimpleNamespace(
        state=state, discovery=None, me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)

    for value in ("true", "yes", "maybe", ""):
        monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", value)
        resp = await server.api_me(SimpleNamespace(query={}))
        body = json.loads(resp.text)
        assert body["autoinstall_enabled"] is False, f"value={value!r}"


@pytest.mark.asyncio
async def test_api_me_autoinstall_env_hard_disable_values(monkeypatch):
    """Only exact ``1`` passes the operator boundary."""
    from one_link.server import UIServer
    me_stub = SimpleNamespace(
        short_id="aaaaaaaa", fingerprint="aa" * 32, hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    state = SimpleNamespace(get_setting=lambda key: "1")
    daemon = SimpleNamespace(
        state=state, discovery=None, me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)

    for value in ("0", "no", "false", "", "maybe", "TRUE"):
        monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", value)
        resp = await server.api_me(SimpleNamespace(query={}))
        body = json.loads(resp.text)
        assert body["autoinstall_enabled"] is False, (
            f"env={value!r} must hard-disable"
        )


@pytest.mark.asyncio
async def test_api_me_reports_locally_proven_standalone_capability(monkeypatch):
    from one_link import update_helper
    from one_link.server import UIServer

    monkeypatch.setattr(
        update_helper,
        "inspect_external_update_capability",
        lambda: update_helper.ExternalUpdateCapability(
            True,
            "available",
            platform="windows-x86_64",
        ),
    )
    me_stub = SimpleNamespace(
        short_id="aaaaaaaa",
        fingerprint="aa" * 32,
        hostname="laptop",
        public_bytes=b"\x00" * 32,
    )
    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=me_stub,
        get_my_presence=lambda: "online",
    )
    server = UIServer(daemon)

    body = json.loads((await server.api_me(SimpleNamespace(query={}))).text)

    assert body["autoinstall_enabled"] is False
    assert body["update_install_available"] is True
    assert body["update_install_reason"] == "available"
    assert body["update_install_platform"] == "windows-x86_64"


@pytest.mark.asyncio
async def test_capability_proof_coalesces_concurrent_ui_refreshes(monkeypatch):
    from one_link import update_helper
    from one_link.server import UIServer

    calls = 0

    def inspect():
        nonlocal calls
        calls += 1
        return update_helper.ExternalUpdateCapability(
            True,
            "available",
            platform="windows-x86_64",
        )

    monkeypatch.setattr(update_helper, "inspect_external_update_capability", inspect)
    server = UIServer(SimpleNamespace(state=None, discovery=None))

    left, right = await asyncio.gather(
        server._external_update_capability(),
        server._external_update_capability(),
    )

    assert left is right
    assert calls == 1
    await server._external_update_capability(fresh=True)
    assert calls == 2

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
    it when state.me.update_install_available is true. This prevents the
    button from briefly flashing on load before JS catches up."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    idx = html.find('id="update-banner-install"')
    assert idx > 0
    # Slice the surrounding 200 chars to inspect the inline style.
    snippet = html[idx:idx + 200]
    assert 'style="display:none"' in snippet, (
        "button should be hidden by default to avoid a flash before "
        "JS reads update_install_available"
    )


def test_check_for_update_uses_dynamic_install_capability():
    html = WEB_INDEX.read_text(encoding="utf-8")
    fn_start = html.find("async function checkForUpdate")
    assert fn_start > 0
    fn_body = html[fn_start:fn_start + 3000]
    assert "state.me?.update_install_available === true" in fn_body
    assert 'installBtn.style.display = canInstall ? "" : "none"' in fn_body


def test_install_button_calls_only_confirmed_install_endpoint():
    html = WEB_INDEX.read_text(encoding="utf-8")
    assert html.count('"/api/update/install"') == 1
    assert "{ confirmed_install: true }" in html
    assert "expected_tag" not in html[html.find('"/api/update/install"') - 200:html.find('"/api/update/install"') + 400]
    assert "expected_release_id" not in html[html.find('"/api/update/install"') - 200:html.find('"/api/update/install"') + 400]
    assert "installAuthenticatedUpdate" in html


def test_update_modal_never_offers_a_floating_package_manager_update():
    html = WEB_INDEX.read_text(encoding="utf-8")
    assert "pip install --upgrade one-link" not in html
    assert "_isFrozenInstall" not in html
    assert "Sigstore bundles, SHA-256 evidence, SBOM" in html
    assert "rollback order" in html
    assert "post-restart daemon/UI health" in html
    assert "not a validated standalone bundle" in html
    assert "matching architecture-labelled artifact" in html


def test_banner_opens_details_and_modal_owns_confirmed_install():
    html = WEB_INDEX.read_text(encoding="utf-8")
    handler_idx = html.find("// The banner first opens the confirmation/details surface")
    assert handler_idx > 0, "JS handler for update-banner-install not found"
    body = html[handler_idx:handler_idx + 2000]
    assert 'getElementById("update-banner-install")' in body
    assert "openUpdateModal();" in body
    assert 'getElementById("update-modal-download")' in body
    assert "installAuthenticatedUpdate();" in body

"""UI markup smoke test — verifies the contract between server.py
and index.html stays consistent.

Browser-free: parses index.html as text + HTMLParser to confirm:
  - every API endpoint the JS calls is registered server-side
  - the IDs the JS bindings reference exist in the markup
  - the v0.4/v0.5 features (paired-only sidebar, discovery modal,
    rendezvous settings, regime indicator) all have their
    corresponding markup wired

If JS asks for an element by ID and that ID doesn't exist, the
feature silently breaks in production. This catches it at test time.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest


HTML_PATH = Path(__file__).parent.parent / "src" / "one_link" / "web" / "index.html"


@pytest.fixture(scope="module")
def html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


class _IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k == "id" and v:
                self.ids.add(v)


@pytest.fixture(scope="module")
def ids(html: str) -> set[str]:
    p = _IdCollector()
    p.feed(html)
    return p.ids


# ─── v0.4: paired-only sidebar + discovery modal ────────────────────

def test_pair_cta_button_present(ids):
    assert "open-discover-modal" in ids, "Sidebar 'Pair a new device' CTA missing"


def test_discovery_modal_markup_present(ids):
    """Modal must have overlay + close button + body container +
    refresh button — JS code references all of these by ID."""
    required = {"discover-overlay", "discover-close", "discover-body",
                "discover-refresh", "discover-status", "discover-title"}
    missing = required - ids
    assert not missing, f"discovery modal missing IDs: {missing}"


def test_discovery_modal_has_phone_fallback(html: str):
    """Phones can be invisible to passive LAN scans, so discovery must
    always expose a direct QR/invite path when no phone is detected."""
    for marker in (
        "function _hasDiscoveredPhone",
        "function _renderPhoneHelp",
        "Don't see your phone?",
        "Pair phone by QR",
        "Phone or tablet",
        "private Wi-Fi addresses",
        "scan the QR from the phone",
        "function startOneSetupDevicePairing()",
        "function _isPersonalDeviceKind",
        "showOnboardingStep(4)",
        "oneSetupAddDevice()",
        "await startOneSetupDevicePairing();",
        "inviteable",
    ):
        assert marker in html


def test_sidebar_header_says_my_devices(html: str):
    """Old header was 'Nearby devices' — v0.4 changed it to 'My devices'
    to reflect the paired-only filter."""
    assert ">My devices<" in html, "Sidebar header was not updated to 'My devices'"


# ─── v0.5.3: rendezvous settings ────────────────────────────────────

def test_rendezvous_settings_inputs_present(ids):
    required = {"set-rendezvous", "rdz-status-dot", "rdz-status-pane",
                "rdz-help-link", "rdz-help-backdrop", "rdz-help-close"}
    missing = required - ids
    assert not missing, f"rendezvous settings UI missing: {missing}"


def test_rendezvous_help_link_calls_help_modal(html: str):
    """Clicking the 'What's a rendezvous?' link must open the help
    modal — checked by ensuring the JS handler references the
    backdrop ID."""
    assert "rdz-help-link" in html
    assert "rdz-help-backdrop" in html
    # Handler bind exists.
    assert re.search(r'\$\("#rdz-help-link"\)\.onclick', html), \
        "rdz-help-link click handler not bound"


def test_settings_save_handler_posts_rendezvous(html: str):
    """The save button must POST to /api/rendezvous when URLs change."""
    assert 'api.post("/api/rendezvous"' in html, \
        "Settings save handler does not POST to /api/rendezvous"


def test_refresh_status_caches_rendezvous_urls(html: str):
    """state.rendezvousUrls must be populated on refreshStatus so the
    empty-state nudge is accurate."""
    assert 'state.rendezvousUrls' in html
    assert 'api.get("/api/rendezvous")' in html


# ─── v0.5.3: regime indicator ───────────────────────────────────────

def test_reach_label_helper_defined(html: str):
    assert "function reachLabel(" in html
    assert "function isPrivateAddress(" in html
    # Used in both sidebar render and conversation header.
    assert html.count("reachLabel(") >= 2


# ─── v0.5.3: empty-state cross-network callout ──────────────────────

def test_empty_state_renders_callout_when_no_rendezvous(html: str):
    """When 0 paired devices AND 0 rendezvous URLs configured, the
    empty state should include a callout to set up rendezvous."""
    assert "empty-state-link" in html
    assert "Set up a rendezvous" in html


# ─── v0.4: peer-list contract ───────────────────────────────────────

def test_peer_list_uses_paired_only_default(html: str):
    """Sidebar's refreshPeers() should NOT pass include_unpaired — it
    must rely on the server's paired-only default."""
    # Match: const { peers } = await api.get("/api/peers");
    assert re.search(
        r'await\s+api\.get\("/api/peers"\)',
        html,
    ), "Sidebar /api/peers call not found"


def test_discovery_modal_passes_include_unpaired(html: str):
    """loadDiscoverable() must hit /api/peers with include_unpaired=1."""
    assert re.search(
        r'/api/peers\?include_unpaired=1',
        html,
    ), "Discovery modal does not pass include_unpaired=1"


# ─── server ↔ UI endpoint contract ──────────────────────────────────

@pytest.fixture(scope="module")
def server_routes() -> set[str]:
    """Extract all `r.add_get/post/delete("/api/...")` paths from
    server.py so we can cross-check the JS API client against actual
    routes."""
    server_py = Path(__file__).parent.parent / "src" / "one_link" / "server.py"
    text = server_py.read_text(encoding="utf-8")
    paths: set[str] = set()
    for m in re.finditer(r'add_(?:get|post|delete)\(\s*r?"([^"]+)"', text):
        paths.add(m.group(1))
    return paths


def test_all_ui_calls_have_server_routes(html: str, server_routes: set[str]):
    """Every /api/... path the JS hits must have a registered route.
    Path-template params ({fp}, {name}, ...) are matched literally
    after a small normalization step."""
    # Find all distinct /api/... usages.
    used: set[str] = set()
    for m in re.finditer(r'["\'`](/api/[^"\'`?\s]+)', html):
        path = m.group(1)
        # Normalize template params: ${var} -> {var}, then any /xxx
        # immediately following /api/<noun>/ becomes a {fp} or {name}.
        path = re.sub(r'\$\{[^}]+\}', '{x}', path)
        used.add(path)

    # For each used path, find a matching route. A used path matches a
    # route if their parts align after collapsing both {x} and {anything}
    # to the same wildcard.
    def _norm(p: str) -> str:
        # Any path segment containing a template expression is dynamic,
        # including typed wire forms such as ``id-${session.id}``.
        return re.sub(r'[^/]*\{[^}]+\}[^/]*', '*', p)

    norm_routes = {_norm(r) for r in server_routes}
    missing = []
    for p in used:
        if _norm(p) not in norm_routes:
            missing.append(p)
    assert not missing, (
        "UI calls these /api/... paths with no server route:\n"
        + "\n".join(f"  - {m}" for m in missing)
    )


# ─── basic structural sanity ────────────────────────────────────────

def test_html_does_not_contain_template_literal_leakage(html: str):
    """Old debug habit: leaving ${...} backticks visible to the user
    because the template literal was inside a single-quoted string by
    accident. Surface check — there shouldn't be raw '${' inside any
    text node."""
    # We're permissive: ${...} inside script tags is fine. Only flag
    # unterminated $\{ occurrences in HTML text, which usually indicates
    # an unintended display.
    visible = re.sub(r'<script[\s\S]*?</script>', '', html, flags=re.IGNORECASE)
    visible = re.sub(r'<style[\s\S]*?</style>', '', visible, flags=re.IGNORECASE)
    assert "${" not in visible, "Stray template literal in visible HTML"


def test_csp_no_inline_event_handlers_in_static_html(html: str):
    """Hand-written `onclick="..."` attributes are a CSP risk and a
    legibility issue — they should live in the JS block. Verify
    static HTML doesn't have them. (Programmatic .onclick = ... in JS
    is fine — those are a different mechanism.)"""
    # Match attributes like onclick="...", oninput="...", etc.
    # Skip everything inside <script>...</script>.
    visible = re.sub(r'<script[\s\S]*?</script>', '', html, flags=re.IGNORECASE)
    handlers = re.findall(
        r'\s(on[a-z]+)\s*=\s*"[^"]*"',
        visible,
    )
    assert not handlers, f"Inline event handlers found: {handlers}"

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
UI_FILES = [
    ROOT / "src" / "one_link" / "web" / "index.html",
    ROOT / "src" / "one_link" / "web" / "peer.html",
]


class _ControlCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.controls: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k: v or "" for k, v in attrs}
        if tag in {"button", "select", "textarea"}:
            self.controls.append((tag, data))
            return
        if tag == "input":
            kind = data.get("type", "text")
            if kind in {"button", "checkbox", "file", "radio", "range", "submit"}:
                self.controls.append((tag, data))


class _LabelCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.label_for: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "label":
            return
        data = {k: v or "" for k, v in attrs}
        target = data.get("for")
        if target:
            self.label_for.add(target)


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.append({k: v or "" for k, v in attrs})


def _camel_data_attr(name: str) -> str:
    parts = name[5:].split("-")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def _script_blocks(html: str) -> str:
    return "\n".join(
        re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, flags=re.I)
    )


def _inline_script_blocks(html: str) -> list[str]:
    return re.findall(
        r"<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>",
        html,
        flags=re.I,
    )


def _is_wired(control: dict[str, str], js: str) -> bool:
    control_id = control.get("id")
    if control_id:
        needles = {
            f"#{control_id}",
            f'getElementById("{control_id}")',
            f"getElementById('{control_id}')",
            f'$("#{control_id}")',
            f"$('#{control_id}')",
        }
        if any(needle in js for needle in needles):
            return True

    name = control.get("name")
    if name and (
        f'name="{name}"' in js
        or f"name='{name}'" in js
        or f'input[name="{name}"]' in js
        or f"input[name='{name}']" in js
    ):
        return True

    for attr in control:
        if attr.startswith("data-"):
            dataset = _camel_data_attr(attr)
            if (
                f"[{attr}]" in js
                or f"[{attr}=" in js
                or attr in js
                or f"dataset.{dataset}" in js
            ):
                return True

    return False


def test_static_ui_controls_have_event_wiring() -> None:
    """Every static user control must be wired directly or by delegation."""
    failures: list[str] = []
    for path in UI_FILES:
        html = path.read_text(encoding="utf-8")
        js = _script_blocks(html)
        parser = _ControlCollector()
        parser.feed(html)
        for tag, control in parser.controls:
            if "disabled" in control:
                continue
            if not _is_wired(control, js):
                label = control.get("id") or control.get("name") or str(control)
                failures.append(f"{path.relative_to(ROOT)}: <{tag}> {label}")

    assert not failures, "Unwired UI controls:\n" + "\n".join(failures)


def test_static_ui_inputs_have_accessible_names() -> None:
    """Inputs/selects/textareas need a visible label or explicit assistive name."""
    failures: list[str] = []
    for path in UI_FILES:
        html = path.read_text(encoding="utf-8")
        labels = _LabelCollector()
        labels.feed(html)
        parser = _ControlCollector()
        parser.feed(html)
        for tag, control in parser.controls:
            control_id = control.get("id")
            # Buttons are covered by their visible text and separate wiring tests.
            if tag == "button":
                continue
            if control.get("type") == "hidden":
                continue
            if (
                control.get("aria-label")
                or control.get("aria-labelledby")
                or control.get("placeholder")
                or control.get("title")
                or (control_id and control_id in labels.label_for)
            ):
                continue
            label = control_id or control.get("name") or str(control)
            failures.append(f"{path.relative_to(ROOT)}: <{tag}> {label}")

    assert not failures, "Controls without accessible names:\n" + "\n".join(failures)


def test_static_ui_links_have_real_targets() -> None:
    """Links should navigate somewhere meaningful, not depend on a bare '#'."""
    failures: list[str] = []
    for path in UI_FILES:
        parser = _LinkCollector()
        parser.feed(path.read_text(encoding="utf-8"))
        for link in parser.links:
            href = link.get("href", "")
            if href and href != "#" and not href.lower().startswith("javascript:"):
                continue
            label = link.get("id") or link.get("class") or str(link)
            failures.append(f"{path.relative_to(ROOT)}: <a> {label}")

    assert not failures, "Links without real targets:\n" + "\n".join(failures)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_static_ui_javascript_parses() -> None:
    """Node syntax-checks inline and standalone browser JS assets."""
    failures: list[str] = []
    standalone = [
        ROOT / "src" / "one_link" / "web" / "sw.js",
        ROOT / "src" / "one_link" / "web" / "dr.js",
    ]
    for path in standalone:
        proc = subprocess.run(
            ["node", "--check", str(path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode:
            failures.append(f"{path.relative_to(ROOT)}:\n{proc.stderr or proc.stdout}")

    for path in UI_FILES + [ROOT / "src" / "one_link" / "web" / "dr_test.html"]:
        html = path.read_text(encoding="utf-8")
        for idx, block in enumerate(_inline_script_blocks(html), start=1):
            js = block.strip()
            if not js:
                continue
            with tempfile.NamedTemporaryFile(
                "w",
                suffix=f"-{path.stem}-{idx}.js",
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(js)
                tmp_path = Path(tmp.name)
            try:
                proc = subprocess.run(
                    ["node", "--check", str(tmp_path)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
            finally:
                tmp_path.unlink(missing_ok=True)
            if proc.returncode:
                failures.append(
                    f"{path.relative_to(ROOT)} inline script {idx}:\n"
                    f"{proc.stderr or proc.stdout}"
                )

    assert not failures, "JavaScript syntax failures:\n" + "\n".join(failures)


# 2026-05-22 audit T2-M: acorn-based scope-aware undefined-call
# check for the daemon's inline JS. Catches the bug class the
# 600+ substring-grep smoke tests miss: a function declared but
# never called, a call site that references a renamed/misspelled
# identifier, dead-code guarded by ``typeof === "function"``.
# The analyzer is at ``tests/js/check_undefined_calls.js`` —
# parses each <script> block with acorn, walks the lexical scope
# chain (function / class / let / const / var hoisting, params,
# destructuring, blocks, catch clauses, imports), and reports any
# bare-identifier call site whose target isn't bound anywhere
# across all script blocks (soft cross-script-scope resolution
# matches the browser's runtime behaviour where script tags
# share the global scope). Verified output: the prior
# uncaught-bug example was ``refreshAll()`` in the auto-recovery
# success path — a ``typeof === "function"`` guard hid the dead
# reference and the post-recovery refresh never fired.

JS_TEST_DIR = ROOT / "tests" / "js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.skipif(
    not (JS_TEST_DIR / "node_modules" / "acorn").is_dir(),
    reason="acorn not installed in tests/js; run `cd tests/js && npm install`",
)
def test_inline_js_no_undefined_call_sites_t2m() -> None:
    """T2-M acorn-scope-aware undefined-call gate.

    Drives ``tests/js/check_undefined_calls.js`` (Node script using
    acorn for AST + manual scope-chain resolution) against
    ``index.html``. The script exits 0 when every bare-identifier
    call resolves; 1 when one or more sites are unresolved.

    To reproduce locally:
        ``node tests/js/check_undefined_calls.js src/one_link/web/index.html``

    To extend coverage: add the new globals / declarations to the
    ``GLOBALS`` allowlist inside ``check_undefined_calls.js`` if
    they're legitimate (browser API, library global, etc.). Real
    undefined references should be fixed in the source.
    """
    target = ROOT / "src" / "one_link" / "web" / "index.html"
    script = JS_TEST_DIR / "check_undefined_calls.js"
    proc = subprocess.run(
        ["node", str(script), str(target)],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            "T2-M undefined-call analyzer flagged sites:\n"
            f"{proc.stdout}{proc.stderr}"
        )


def test_trace_clearing_controls_are_exposed() -> None:
    html = (ROOT / "src" / "one_link" / "web" / "index.html").read_text(
        encoding="utf-8",
    )
    for needle in [
        'id="btn-clear-file-traces"',
        'id="btn-clear-folder-traces"',
        'id="btn-clear-activity-traces"',
        'id="storage-clear-chat"',
        'id="storage-clear-files"',
        'id="storage-clear-folders"',
        'id="storage-clear-activity"',
        'id="storage-wipe-local"',
        "/api/traces/",
        "/api/traces/wipe",
        "wipe local traces",
    ]:
        assert needle in html


def test_received_files_are_collapsed_by_identity() -> None:
    html = (ROOT / "src" / "one_link" / "web" / "index.html").read_text(
        encoding="utf-8",
    )
    idx = html.find('if (state.filesMode === "received")')
    snippet = html[idx:idx + 4200]
    assert "const grouped = []" in snippet
    assert "byKey" in snippet
    assert "canonicalInboxFileFamily" in html
    assert r"\s+\(\d+\)$" in html
    assert "display_name" in snippet
    assert "members" in snippet
    assert "copies" in snippet
    assert "duplicate inbox entries are collapsed" in snippet
    assert "file-actions" in snippet
    assert "Show all ${f.copies} copies" in html
    assert "duplicate-list" in html
    assert "dup-open" in html
    assert "Latest ${fmtBytes(f.size)}" in snippet


def test_sent_files_default_to_compact_details() -> None:
    html = (ROOT / "src" / "one_link" / "web" / "index.html").read_text(
        encoding="utf-8",
    )
    idx = html.find('const sent = state.transfers')
    snippet = html[idx:idx + 2600]
    assert "renderPrimaryTransferSummary" in html
    assert "renderTransferDetails" in html
    assert 'el("div", "sent-summary")' in html
    assert "renderTransferDetails(t)" in snippet
    assert "transfer-details" in html


def test_activity_surface_uses_progressive_disclosure() -> None:
    html = (ROOT / "src" / "one_link" / "web" / "index.html").read_text(
        encoding="utf-8",
    )
    assert 'id="one-now"' in html
    assert "function renderOneNow()" in html
    assert 'id="one-now-send"' in html
    assert 'id="one-now-devices"' in html
    assert 'id="one-now-privacy"' in html
    assert 'id="activity-nearby-panel"' in html
    assert 'id="activity-nearby-close"' in html
    assert 'id="one-health-guide-backdrop"' in html
    assert "openOneHealthGuide();" in html
    assert "closeOneHealthGuide();" in html
    assert 'id="one-health-guide-autopilot-button"' in html
    assert '$("#one-health-guide-grid")?.addEventListener("click"' in html
    assert '$("#one-health-guide-grid")?.addEventListener("keydown"' in html
    assert "setOneHealthGuideFocus(card.dataset.oneHealthFocus || \"\")" in html
    assert '$("#one-health-guide-autopilot-button")?.addEventListener("click"' in html
    assert "openOneHealthGuideDestination(action);" in html
    assert "returnToOneHealthGuideIfPending();" in html
    assert "#privacy-panel-overlay.show" in html
    assert 'role", "button"' in html
    assert 'tabindex", "0"' in html
    assert 'id="activity-advanced-tools"' in html
    assert "Advanced fabric tools" in html
    assert "#mesh-panel" in html
    assert "scrollbar-gutter: stable" in html
    assert "grid-template-columns: repeat(auto-fit, minmax(82px, 1fr));" in html
    assert "async function loadActivityNearby" in html
    assert "async function toggleActivityNearby()" in html
    assert "async function _openActivityNearbyFromTile()" in html
    assert "function closeActivityNearby()" in html
    assert 'card.style.display = nearbyOpen ? "none" : "";' in html
    assert "_openActivityNearbyFromTile()" in html
    assert "function nearbyCount()" in html
    assert "function updateNearbyMetric()" in html
    assert 'aria-expanded", open ? "true" : "false"' in html
    assert 'closeActivityNearby();' in html
    assert 'await loadActivityNearby({ force: true });' in html
    assert 'classList.toggle("is-complete", !!setup.completed)' in html
    assert 'id="self-mesh-remote-actions"' in html
    assert 'id="self-mesh-join-actions"' in html
    assert 'id="self-mesh-safety-actions"' in html
    assert "Send or pull from another device" in html
    assert "Add this device with an invite" in html
    assert "Device safety" in html
    assert 'class="sm-actions sm-primary-actions"' in html

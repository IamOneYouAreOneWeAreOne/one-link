"""/api/update/plan reaches a user, and its rendering is EXECUTED, not grepped.

The endpoint was registered, authenticated, and correct -- and no shipped asset
called it, found by asking which registered routes have no consumer. It sits on
the update path, alongside `_external_update_capability(fresh=True)`, the code
changed to fix macOS self-install. A regression in it would have been silent.

It is now wired into the update modal: when this build can self-install, the
modal says what the install would download and which release it is pinned to.

These tests run the real functions under Node rather than asserting that
substrings appear in the HTML. A static check can prove the code is present; it
cannot prove `_formatBytes(-1)` does not render "-0.0 KB", or that a failed
fetch leaves the panel hidden rather than showing an empty box. Both of those
are what a user would actually see.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INDEX = REPO / "src" / "one_link" / "web" / "index.html"

_NODE = shutil.which("node")

# Skipping locally is fine; skipping on CI is how a gate goes dark. Every
# GitHub-hosted runner ships Node, so an absence there is a broken environment,
# not an unsupported one -- and a silent skip would let this whole file stop
# running while the summary line still said "passed".
if _NODE is None and os.environ.get("CI"):
    raise RuntimeError(
        "node is missing on CI, so the update-plan rendering tests would "
        "silently not run. Install node in the workflow rather than letting "
        "this file skip."
    )

pytestmark = pytest.mark.skipif(
    _NODE is None,
    reason="node is required to execute the extracted browser functions",
)


def _extract(name: str, end_marker: str) -> str:
    source = INDEX.read_text(encoding="utf-8")
    start = source.index(name)
    stop = source.index(end_marker, start + len(name))
    return source[start:stop]


def _run_node(script: str) -> object:
    result = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO,
    )
    assert result.returncode == 0, (
        f"node failed ({result.returncode}):\n{result.stderr}\n{result.stdout}"
    )
    # A silent success with no output is the failure mode that lets a broken
    # harness look green, so require parseable output rather than trusting the
    # exit code.
    assert result.stdout.strip(), f"node produced no output; stderr:\n{result.stderr}"
    return json.loads(result.stdout.strip().splitlines()[-1])


# ── _formatBytes, executed ────────────────────────────────────────────


def test_format_bytes_is_correct_and_refuses_nonsense() -> None:
    """Includes the hostile inputs, because `size` comes off the network.

    `plan.artifact.size` is JSON from an HTTP response. A negative or NaN size
    must render as nothing rather than as a confident wrong number.
    """
    body = _extract("function _formatBytes", "\n  // Resolve /api/update/plan")
    cases = [
        0, 512, 1023, 1024, 1536, 10 * 1024,
        1024 ** 2, 121_000_000, 5 * 1024 ** 3,
        -1, None, "big", float("nan"),
    ]
    script = textwrap.dedent(f"""
        {body}
        const cases = {json.dumps(cases).replace("NaN", "Number.NaN")};
        console.log(JSON.stringify(cases.map(_formatBytes)));
    """)
    got = _run_node(script)
    assert got == [
        "0 B", "512 B", "1023 B", "1.0 KB", "1.5 KB", "10 KB",
        "1.0 MB", "115 MB", "5.0 GB",
        "", "", "", "",
    ], got


# ── _fillUpdatePlan, executed against a fake DOM ──────────────────────


_HARNESS = r"""
// Minimal DOM: only what _fillUpdatePlan touches.
function makeEl(tag) {
  return {
    tag, className: "", _text: "", children: [], hidden: false,
    set textContent(v) { this._text = String(v); this.children = []; },
    get textContent() {
      return this._text + this.children.map(c =>
        typeof c === "string" ? c : c.textContent).join("");
    },
    set innerHTML(v) { this._text = ""; this.children = []; },
    get innerHTML() { return this.textContent; },
    appendChild(c) { this.children.push(c); return c; },
    append(...xs) { for (const x of xs) this.children.push(x); },
  };
}
const document = { createElement: makeEl };
const host = makeEl("div");
host.hidden = true;
const $ = (sel) => (sel === "#um-plan" ? host : null);
// Parenthesised: `async () => {a:1}` parses the braces as a function body,
// not an object literal, and returns undefined -- which would have made every
// "panel stays hidden" assertion below pass for the wrong reason.
const api = { get: async () => (API_RESULT) };
"""


def _render(api_result: str) -> dict:
    # _fillUpdatePlan calls _formatBytes, so both real functions are loaded.
    # Stubbing the formatter would have tested the harness, not the product.
    body = (
        _extract("function _formatBytes", "\n  // Resolve /api/update/plan")
        + _extract("async function _fillUpdatePlan", "\n  function openUpdateModal")
    )
    script = (
        _HARNESS.replace("API_RESULT", api_result)
        + body
        + textwrap.dedent("""
        _fillUpdatePlan().then(() => {
          console.log(JSON.stringify({
            hidden: host.hidden,
            text: host.textContent,
            children: host.children.length,
          }));
        }).catch(e => { console.error(e); process.exit(3); });
        """)
    )
    return _run_node(script)


def test_a_resolved_plan_names_the_artifact_and_its_size() -> None:
    out = _render(
        '{status:"ready", tag:"v0.21.0", '
        'artifact:{filename:"one-link-windows.zip", size:121000000}}'
    )
    assert out["hidden"] is False
    assert "one-link-windows.zip" in out["text"]
    assert "115 MB" in out["text"]
    assert "v0.21.0" in out["text"]


def test_the_copy_does_not_claim_the_displayed_plan_was_verified() -> None:
    """The plan is presentation data; the helper does the authentication.

    Wording that implied this panel had verified anything would be a security
    claim made by a screen that checks nothing. It may describe what the
    updater will do -- it may not report that as already done.
    """
    out = _render(
        '{status:"ready", tag:"v0.21.0", '
        'artifact:{filename:"a.zip", size:1024}}'
    )
    text = out["text"].lower()
    assert "signatures are checked by the updater before" in text
    for forbidden in ("verified signature", "signature verified", "authenticated ✓"):
        assert forbidden not in text


@pytest.mark.parametrize(
    "api_result,label",
    [
        ("null", "null body"),
        ("{status:'error', error:'boom'}", "server-reported error"),
        ("{status:'ready', tag:'v1'}", "no artifact in the plan"),
        ("{status:'disabled'}", "policy-disabled updates"),
    ],
)
def test_an_unusable_plan_leaves_the_panel_hidden(api_result: str, label: str) -> None:
    """Never show an empty box where a description should be.

    Each of these is a real response this endpoint can return: 409 when the
    runtime cannot self-install, `disabled` under sovereignty policy, and
    `{"status": "error"}` which the handler returns with HTTP 200.
    """
    out = _render(api_result)
    assert out["hidden"] is True, f"panel was shown for {label}"
    assert out["children"] == 0, f"panel rendered content for {label}"


def test_a_failing_request_cannot_break_the_modal() -> None:
    """The install must not depend on the description of the install."""
    # _fillUpdatePlan calls _formatBytes, so both real functions are loaded.
    # Stubbing the formatter would have tested the harness, not the product.
    body = (
        _extract("function _formatBytes", "\n  // Resolve /api/update/plan")
        + _extract("async function _fillUpdatePlan", "\n  function openUpdateModal")
    )
    script = (
        _HARNESS.replace("api = { get: async () => (API_RESULT) }",
                         "api = { get: async () => { throw new Error('offline'); } }")
        + body
        + textwrap.dedent("""
        _fillUpdatePlan().then(() => {
          console.log(JSON.stringify({hidden: host.hidden, ok: true}));
        }).catch(() => { console.log(JSON.stringify({ok: false})); });
        """)
    )
    out = _run_node(script)
    assert out["ok"] is True, "a failed fetch propagated out of _fillUpdatePlan"
    assert out["hidden"] is True


# ── the wiring itself ─────────────────────────────────────────────────


def test_the_plan_is_requested_only_when_this_build_can_self_install() -> None:
    """A user who must download manually gets the size from their browser.

    Resolving a plan the daemon cannot act on would be a network request with
    nothing behind it, and on the rolling channel it would 409 every time.
    """
    source = INDEX.read_text(encoding="utf-8")
    assert "if (canInstall) _fillUpdatePlan();" in source, (
        "the plan fetch is no longer gated on canInstall"
    )


def test_a_stale_plan_cannot_survive_into_a_later_open() -> None:
    """Reopening the modal for a NEWER release must not show the old size.

    The panel is populated asynchronously, so without an explicit reset the
    previous release's artifact stays on screen until the new fetch lands --
    and stays forever if that fetch fails.
    """
    source = INDEX.read_text(encoding="utf-8")
    start = source.index("function openUpdateModal")
    prelude = source[start:start + 900]
    assert 'planHost.hidden = true' in prelude
    assert 'planHost.innerHTML = ""' in prelude
